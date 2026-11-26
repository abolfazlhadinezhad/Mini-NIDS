"""RFC 1035 wire decoder with bounded, cycle-safe compression traversal."""

import struct
from dataclasses import dataclass
from ipaddress import ip_address

from .errors import ParseError, need


@dataclass(frozen=True, slots=True)
class Question:
    name: str
    type: int
    cls: int


@dataclass(frozen=True, slots=True)
class ResourceRecord:
    name: str
    type: int
    cls: int
    ttl: int
    value: str


@dataclass(frozen=True, slots=True)
class DNS:
    transaction_id: int
    flags: int
    questions: tuple[Question, ...]
    answers: tuple[ResourceRecord, ...]
    authorities: tuple[ResourceRecord, ...]
    additionals: tuple[ResourceRecord, ...]

    @property
    def response(self) -> bool:
        return bool(self.flags & 0x8000)

    @property
    def rcode(self) -> int:
        return self.flags & 15

    @property
    def truncated(self) -> bool:
        return bool(self.flags & 0x0200)


def read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels, visited = [], set()
    end = None
    expanded = 1
    while True:
        if offset in visited or len(visited) >= 128:
            raise ParseError("DNS compression loop/depth")
        visited.add(offset)
        need(data, offset + 1, "DNS name")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            need(data, offset + 2, "DNS pointer")
            target = ((length & 0x3F) << 8) | data[offset + 1]
            if target >= offset:
                raise ParseError("DNS compression pointer must refer backward")
            if end is None:
                end = offset + 2
            offset = target
            continue
        if length & 0xC0:
            raise ParseError("invalid DNS label type")
        offset += 1
        if length == 0:
            return ".".join(labels).lower() + ".", end if end is not None else offset
        need(data, offset + length, "DNS label")
        expanded += length + 1
        if expanded > 255:
            raise ParseError("DNS expanded name too long")
        # Escaping prevents literal dots/nonprintable bytes from colliding as keys.
        labels.append(
            "".join(
                chr(b) if 33 <= b <= 126 and b not in (46, 92) else f"\\{b:03d}"
                for b in data[offset : offset + length]
            )
        )
        offset += length


def parse_dns(data: bytes) -> DNS:
    need(data, 12, "DNS header")
    txid, flags, nq, na, nn, nx = struct.unpack_from("!6H", data)
    if nq + na + nn + nx > 1024:
        raise ParseError("DNS question/record safety limit exceeded")
    offset, questions = 12, []
    for _ in range(nq):
        name, offset = read_name(data, offset)
        need(data, offset + 4, "DNS question")
        kind, cls = struct.unpack_from("!HH", data, offset)
        questions.append(Question(name, kind, cls))
        offset += 4
    sections = []
    for count in (na, nn, nx):
        records = []
        for _ in range(count):
            name, offset = read_name(data, offset)
            need(data, offset + 10, "DNS resource record")
            kind, cls, ttl, length = struct.unpack_from("!HHIH", data, offset)
            start, end = offset + 10, offset + 10 + length
            need(data, end, "DNS RDATA")
            value = data[start:end].hex()
            if kind in (1, 28):
                if length != (4 if kind == 1 else 16):
                    raise ParseError("invalid DNS address RDLENGTH")
                value = str(ip_address(data[start:end]))
            elif kind in (2, 5, 12):
                value, used = read_name(data, start)
                if used != end:
                    raise ParseError("DNS name does not match RDLENGTH")
            elif kind in (15, 33):
                prefix = 2 if kind == 15 else 6
                if length < prefix + 1:
                    raise ParseError("DNS MX/SRV RDATA too short")
                nums = struct.unpack_from("!" + "H" * (prefix // 2), data, start)
                target, used = read_name(data, start + prefix)
                if used != end:
                    raise ParseError("DNS MX/SRV name exceeds RDLENGTH")
                value = " ".join(map(str, nums)) + " " + target
            elif kind == 16:
                chunks, pos = [], start
                while pos < end:
                    size = data[pos]
                    pos += 1
                    if pos + size > end:
                        raise ParseError("DNS TXT string exceeds RDLENGTH")
                    chunks.append(data[pos : pos + size].decode("utf-8", errors="backslashreplace"))
                    pos += size
                value = " | ".join(chunks)
            records.append(ResourceRecord(name, kind, cls, ttl, value))
            offset = end
        sections.append(tuple(records))
    return DNS(txid, flags, tuple(questions), *sections)
