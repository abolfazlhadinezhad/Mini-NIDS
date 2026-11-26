"""Classic PCAP envelopes only; no library protocol dissection."""

import struct
from dataclasses import dataclass
from decimal import Decimal
from typing import BinaryIO

from .errors import CaptureError

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


@dataclass(frozen=True, slots=True)
class Record:
    timestamp_ns: int
    data: bytes
    original_length: int
    index: int = 0

    @property
    def timestamp(self) -> Decimal:
        return Decimal(self.timestamp_ns) / Decimal(1_000_000_000)

    @property
    def timestamp_text(self) -> str:
        return f"{self.timestamp_ns // 1_000_000_000}.{self.timestamp_ns % 1_000_000_000:09d}"


class PcapReader:
    """Read exactly one bounded record at a time. Caller owns the input handle."""

    def __init__(self, stream: BinaryIO, max_packet_bytes: int = 1_048_576):
        self.stream = stream
        self.max_packet_bytes = max_packet_bytes
        head = stream.read(24)
        if len(head) != 24:
            raise CaptureError("incomplete PCAP global header")
        if head[:4] == b"\x0a\x0d\x0d\x0a":
            raise CaptureError("PCAPNG unsupported; convert to Ethernet PCAP with editcap -F pcap")
        if head[:4] not in MAGICS:
            raise CaptureError("unsupported PCAP magic")
        self.endian, self.ns_factor = MAGICS[head[:4]]
        major, minor, _, _, self.snaplen, network = struct.unpack(self.endian + "HHiIII", head[4:])
        if (major, minor) != (2, 4):
            raise CaptureError(f"unsupported PCAP version {major}.{minor}")
        self.linktype = network & 0xFFFF
        if self.linktype != 1:
            raise CaptureError(f"unsupported linktype {self.linktype}; Ethernet (1) required")
        # Extended PCAP linktype metadata can describe FCS bytes.
        self.fcs_length = ((network >> 28) & 0xF) * 2 if network & (1 << 26) else 0
        if not self.snaplen:
            raise CaptureError("PCAP snaplen must be positive")

    def __iter__(self):
        index = 0
        while True:
            head = self.stream.read(16)
            if not head:
                return
            if len(head) != 16:
                raise CaptureError(f"incomplete record header after packet {index}")
            seconds, fraction, captured, original = struct.unpack(self.endian + "IIII", head)
            if fraction >= 1_000_000_000 // self.ns_factor:
                raise CaptureError(f"invalid timestamp fraction at packet {index + 1}")
            if captured > self.max_packet_bytes:
                raise CaptureError(f"packet {index + 1} exceeds configured capture byte limit")
            if captured > self.snaplen or captured > original:
                raise CaptureError(f"inconsistent capture/original/snaplen at packet {index + 1}")
            data = self.stream.read(captured)
            if len(data) != captured:
                raise CaptureError(f"incomplete record body at packet {index + 1}")
            index += 1
            yield Record(seconds * 1_000_000_000 + fraction * self.ns_factor, data, original, index)
