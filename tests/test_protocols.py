import random
import struct

import pytest

from mininids.capture import Record
from mininids.protocols import parse_packet
from tests.builders import arp, ethernet, ipv4, tcp, udp


def packet(data, original=None):
    return parse_packet(Record(123, data, len(data) if original is None else original))


def test_tcp_fields():
    p = packet(ethernet(ipv4(tcp(flags=0x12, seq=400, ack=900, payload=b"xyz"))))
    assert p.ethernet.src == "02:00:00:00:00:10"
    assert p.ip.total_length == 43
    assert p.ip.identification == 7 and p.ip.ttl == 64
    assert p.tcp.sequence == 400 and p.tcp.acknowledgment == 900
    assert p.tcp.payload_length == 3 and p.tcp.captured_payload == b"xyz"
    assert p.tcp.window == 8192 and p.tcp.flags == 0x12


def test_arp_and_vlan():
    p = packet(ethernet(arp(), 0x0806, vlan=100))
    assert p.ethernet.vlan_tags == (100,)
    assert p.arp.sender_ip == "10.0.0.1"
    assert p.arp.operation == 2
    assert not p.malformed


def test_stacked_vlan():
    data = ethernet(struct.pack("!HHHH", 1, 0x8100, 2, 0x0800) + ipv4(tcp()), 0x88A8)
    assert packet(data).ethernet.vlan_tags == (1, 2)


def test_capture_truncation_retains_transport():
    raw = ethernet(ipv4(tcp(payload=b"x" * 100)))
    p = packet(raw[:60], len(raw))
    assert p.truncated and not p.malformed
    assert p.tcp.payload_length == 100
    assert len(p.tcp.captured_payload) == 6


def test_bad_total_length_is_malformed():
    assert packet(ethernet(ipv4(tcp(), total=2000))).malformed


@pytest.mark.parametrize("fragment", [0x2000, 1, 0x2001])
def test_fragments_never_feed_transport(fragment):
    p = packet(ethernet(ipv4(tcp(), flags_offset=fragment)))
    assert p.ip.fragmented and p.tcp is None
    assert not p.malformed
    assert p.ip.fragment_offset == (fragment & 0x1FFF) * 8


@pytest.mark.parametrize("cut", list(range(0, 54)))
def test_all_tcp_truncations_are_safe(cut):
    raw = ethernet(ipv4(tcp()))
    p = packet(raw[:cut], len(raw))
    assert p.truncated


def test_icmp_quote_is_not_dns():
    quote = ipv4(udp(b"", dport=53), proto=17)
    p = packet(ethernet(ipv4(b"\x03\x03\0\0" + b"\0" * 4 + quote, proto=1)))
    assert p.icmp.type == 3 and p.icmp.code == 3
    assert p.icmp.embedded_ip.protocol == 17
    assert p.icmp.embedded_dst_port == 53
    assert p.dns is None


def test_unsupported_and_checksum_offload():
    assert packet(ethernet(b"anything", 0x86DD)).unsupported
    p = packet(ethernet(ipv4(tcp())))
    assert not p.malformed  # Deliberately zero checksums accepted.


def test_udp_length_validation():
    raw = struct.pack("!HHHH", 1, 2, 65535, 0)
    assert packet(ethernet(ipv4(raw, proto=17))).malformed


def test_ipv4_and_tcp_options():
    segment = bytearray(tcp(payload=b"abc"))
    segment[12] = 0x60  # 24-byte TCP header.
    segment[20:20] = b"\x01\x01\0\0"
    datagram = bytearray(ipv4(bytes(segment)))
    datagram[0] = 0x46  # 24-byte IPv4 header.
    datagram[2:4] = struct.pack("!H", len(datagram) + 4)
    datagram[20:20] = b"\x01\x01\0\0"
    p = packet(ethernet(bytes(datagram)))
    assert p.ip.header_length == 24 and p.tcp.header_length == 24
    assert p.tcp.payload_length == 3
    assert p.tcp.captured_payload == b"abc"


def test_ns_flag_and_ethernet_padding():
    segment = bytearray(tcp())
    segment[12] |= 1
    p = packet(ethernet(ipv4(bytes(segment))) + b"\0" * 20)
    assert p.tcp.flags == 0x102 and p.tcp.payload_length == 0


def test_random_inputs_do_not_crash():
    rng = random.Random(512)
    for _ in range(2000):
        data = rng.randbytes(rng.randrange(256))
        packet(data)
