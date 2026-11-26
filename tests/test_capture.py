import struct
from io import BytesIO

import pytest

from mininids.capture import PcapReader
from mininids.errors import CaptureError
from tests.builders import pcap


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nano", [False, True])
def test_variants(endian, nano):
    ns = 1_700_000_000_123_456_789 if nano else 1_700_000_000_123_456_000
    reader = PcapReader(BytesIO(pcap([(ns, b"abc", 100)], endian, nano)))
    record = next(iter(reader))
    assert record.timestamp_ns == ns
    assert str(record.timestamp) == ("1700000000.123456789" if nano else "1700000000.123456")
    assert record.original_length == 100
    assert record.data == b"abc"
    assert reader.snaplen == 65535


@pytest.mark.parametrize(
    "data", [b"", b"\0" * 24, pcap([]) + b"\1", pcap([(0, b"abc", None)])[:-1]]
)
def test_invalid_capture(data):
    with pytest.raises(CaptureError):
        list(PcapReader(BytesIO(data)))


def test_limits_and_linktype():
    with pytest.raises(CaptureError, match="linktype"):
        PcapReader(BytesIO(pcap([], linktype=113)))
    with pytest.raises(CaptureError, match="byte limit"):
        list(PcapReader(BytesIO(pcap([(0, b"abcd", None)])), max_packet_bytes=2))
    with pytest.raises(CaptureError, match="inconsistent"):
        list(PcapReader(BytesIO(pcap([(0, b"abcd", 1)]))))
    with pytest.raises(CaptureError, match="snaplen"):
        PcapReader(BytesIO(pcap([], snaplen=0)))


def test_bad_fraction():
    raw = pcap([]) + struct.pack("<IIII", 0, 1_000_000, 0, 0)
    with pytest.raises(CaptureError, match="fraction"):
        list(PcapReader(BytesIO(raw)))


def test_streams_without_unbounded_reads():
    class Guard(BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 65535
            return super().read(size)

    assert len(list(PcapReader(Guard(pcap([(0, b"abc", None)] * 200))))) == 200
