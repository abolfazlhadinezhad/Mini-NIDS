import random
import struct

import pytest

from mininids.dns import parse_dns, read_name
from mininids.errors import ParseError
from tests.builders import dns, ethernet, ipv4, name, udp
from tests.test_protocols import packet


def test_query_response_and_compression():
    q = parse_dns(dns())
    r = parse_dns(dns(response=True))
    assert not q.response and r.response
    assert q.questions[0].name == "example.test."
    assert r.answers[0].value == "203.0.113.5"
    assert r.answers[0].ttl == 60
    assert r.answers[0].name == q.questions[0].name
    assert r.rcode == 0


@pytest.mark.parametrize(
    "kind,rdata,expected",
    [
        (28, bytes.fromhex("20010db8000000000000000000000001"), "2001:db8::1"),
        (5, b"\xc0\x0c", "example.test."),
        (15, b"\0\x0a\xc0\x0c", "10 example.test."),
        (16, b"\x03abc\x01d", "abc | d"),
        (65000, b"abc", "616263"),
    ],
)
def test_record_types(kind, rdata, expected):
    raw = struct.pack("!6H", 1, 0x8180, 1, 1, 0, 0) + name("example.test")
    raw += struct.pack("!HH", 1, 1) + b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 90, len(rdata))
    assert parse_dns(raw + rdata).answers[0].value == expected


@pytest.mark.parametrize(
    "raw", [b"\xc0\x00", b"\xc0\x02\0", b"\x80", b"\x40", b"\x03ab", b"\xc0", b"\x3f" + b"a" * 63]
)
def test_bad_names(raw):
    with pytest.raises(ParseError):
        read_name(raw, 0)


def test_name_length_limit():
    with pytest.raises(ParseError, match="too long"):
        read_name((b"\x3f" + b"a" * 63) * 4 + b"\0", 0)


def test_header_count_limit_and_nxdomain():
    with pytest.raises(ParseError, match="limit"):
        parse_dns(struct.pack("!6H", 1, 0, 65535, 0, 0, 0))
    assert parse_dns(struct.pack("!6H", 1, 0x8183, 0, 0, 0, 0)).rcode == 3


def test_udp_dns_and_mdns():
    assert packet(ethernet(ipv4(udp(dns()), proto=17))).dns.transaction_id == 123
    assert packet(ethernet(ipv4(udp(dns(), dport=5353), proto=17))).dns is None


def test_dns_truncation_is_not_fabricated_answer():
    raw = ethernet(ipv4(udp(dns(response=True)), proto=17))
    p = packet(raw[:-2], len(raw))
    assert p.truncated and not p.malformed and p.dns is None


def test_fuzz_dns_safe():
    rng = random.Random(20)
    for _ in range(1000):
        try:
            parse_dns(rng.randbytes(rng.randrange(100)))
        except ParseError:
            pass
