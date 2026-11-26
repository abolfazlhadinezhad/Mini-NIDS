from decimal import Decimal

from mininids.capture import Record
from mininids.protocols import parse_packet
from tests.builders import ethernet, ipv4, tcp
from tools.compare_tshark import expected_fields


def test_reference_adapter_compares_raw_sequence_numbers_and_timestamps():
    raw = ethernet(ipv4(tcp(seq=0xFFFFFFFF)), vlan=300)
    p = parse_packet(Record(1700000000123456789, raw, len(raw), 1))
    expected = expected_fields(p)
    assert expected["frame.time_epoch"] == Decimal("1700000000.123456789")
    assert expected["vlan.id"] == 300
    assert expected["tcp.seq_raw"] == 0xFFFFFFFF
