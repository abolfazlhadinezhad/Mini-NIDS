"""Manual L2/L3/L4 decoding with retained lower-layer fields on parse errors."""

import struct
from dataclasses import dataclass, field
from ipaddress import IPv4Address

from .capture import Record
from .errors import ParseError, need

FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS = (1 << i for i in range(9))
FLAG_NAMES = {
    FIN: "FIN",
    SYN: "SYN",
    RST: "RST",
    PSH: "PSH",
    ACK: "ACK",
    URG: "URG",
    ECE: "ECE",
    CWR: "CWR",
    NS: "NS",
}


def mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


@dataclass(frozen=True, slots=True)
class Ethernet:
    src: str
    dst: str
    ethertype: int
    vlan_tags: tuple[int, ...]
    header_length: int


@dataclass(frozen=True, slots=True)
class ARP:
    operation: int
    sender_mac: str
    sender_ip: str
    target_mac: str
    target_ip: str
    hardware_type: int = 1
    protocol_type: int = 0x0800


@dataclass(frozen=True, slots=True)
class IPv4:
    src: str
    dst: str
    ttl: int
    protocol: int
    total_length: int
    identification: int
    fragment_offset: int
    flags: int
    header_length: int
    checksum: int

    @property
    def fragmented(self) -> bool:
        return bool(self.fragment_offset or self.flags & 1)


@dataclass(frozen=True, slots=True)
class TCP:
    src_port: int
    dst_port: int
    sequence: int
    acknowledgment: int
    flags: int
    window: int
    payload_length: int
    captured_payload: bytes
    header_length: int
    checksum: int


@dataclass(frozen=True, slots=True)
class UDP:
    src_port: int
    dst_port: int
    length: int
    checksum: int
    captured_payload: bytes


@dataclass(frozen=True, slots=True)
class ICMP:
    type: int
    code: int
    checksum: int
    embedded_ip: IPv4 | None = None
    embedded_src_port: int | None = None
    embedded_dst_port: int | None = None


@dataclass(slots=True)
class Packet:
    record: Record
    ethernet: Ethernet | None = None
    arp: ARP | None = None
    ip: IPv4 | None = None
    tcp: TCP | None = None
    udp: UDP | None = None
    icmp: ICMP | None = None
    dns: object = None
    malformed: list[str] = field(default_factory=list)
    truncated: list[str] = field(default_factory=list)
    unsupported: str | None = None


def parse_ethernet(data: bytes) -> Ethernet:
    need(data, 14, "Ethernet")
    dst, src, etype = struct.unpack_from("!6s6sH", data)
    offset, tags = 14, []
    while etype in (0x8100, 0x88A8, 0x9100):
        if len(tags) >= 4:
            raise ParseError("more than four VLAN tags unsupported")
        need(data, offset + 4, "VLAN")
        tci, etype = struct.unpack_from("!HH", data, offset)
        tags.append(tci)
        offset += 4
    return Ethernet(mac(src), mac(dst), etype, tuple(tags), offset)


def parse_arp(data: bytes) -> ARP:
    need(data, 8, "ARP")
    hardware, protocol, hlen, plen, operation = struct.unpack_from("!HHBBH", data)
    if (hardware, protocol, hlen, plen) != (1, 0x0800, 6, 4):
        raise ParseError("unsupported ARP address format")
    need(data, 28, "ARP addresses")
    if operation not in (1, 2):
        raise ParseError("unsupported ARP operation")
    return ARP(
        operation,
        mac(data[8:14]),
        str(IPv4Address(data[14:18])),
        mac(data[18:24]),
        str(IPv4Address(data[24:28])),
        hardware,
        protocol,
    )


def parse_ipv4(data: bytes) -> IPv4:
    need(data, 20, "IPv4")
    version_ihl, _, total, ident, fragment, ttl, proto, checksum, src, dst = struct.unpack_from(
        "!BBHHHBBH4s4s", data
    )
    ihl = (version_ihl & 15) * 4
    if version_ihl >> 4 != 4 or ihl < 20 or total < ihl:
        raise ParseError("invalid IPv4 version/IHL/total length")
    need(data, ihl, "IPv4 options")
    return IPv4(
        str(IPv4Address(src)),
        str(IPv4Address(dst)),
        ttl,
        proto,
        total,
        ident,
        (fragment & 0x1FFF) * 8,
        fragment >> 13,
        ihl,
        checksum,
    )


def parse_tcp(data: bytes, expected: int) -> TCP:
    if expected < 20:
        raise ParseError("IPv4 payload too short for TCP")
    need(data, 20, "TCP")
    sport, dport, seq, ack, offset_ns, flags, window, checksum, _ = struct.unpack_from(
        "!HHIIBBHHH", data
    )
    hlen = (offset_ns >> 4) * 4
    if hlen < 20 or hlen > expected:
        raise ParseError("invalid TCP data offset")
    need(data, hlen, "TCP options")
    return TCP(
        sport,
        dport,
        seq,
        ack,
        flags | ((offset_ns & 1) << 8),
        window,
        expected - hlen,
        data[hlen:expected],
        hlen,
        checksum,
    )


def parse_udp(data: bytes, expected: int) -> UDP:
    if expected < 8:
        raise ParseError("IPv4 payload too short for UDP")
    need(data, 8, "UDP")
    sport, dport, length, checksum = struct.unpack_from("!HHHH", data)
    if length < 8 or length > expected:
        raise ParseError("invalid UDP length")
    return UDP(sport, dport, length, checksum, data[8:length])


def parse_icmp(data: bytes, expected: int) -> ICMP:
    if expected < 8:
        raise ParseError("IPv4 payload too short for ICMP")
    need(data, 8, "ICMP")
    kind, code, checksum = struct.unpack_from("!BBH", data)
    inner = None
    sport = dport = None
    # Quotes are partial original datagrams, not standalone transport/DNS packets.
    if kind in (3, 4, 5, 11, 12) and len(data) >= 28:
        try:
            inner = parse_ipv4(data[8:])
            offset = 8 + inner.header_length
            if inner.fragment_offset == 0 and inner.protocol in (6, 17) and len(data) >= offset + 4:
                sport, dport = struct.unpack_from("!HH", data, offset)
        except ParseError:
            pass
    return ICMP(kind, code, checksum, inner, sport, dport)


def parse_packet(record: Record) -> Packet:
    packet = Packet(record)
    if len(record.data) < record.original_length:
        packet.truncated.append("capture length smaller than wire length")
    try:
        packet.ethernet = eth = parse_ethernet(record.data)
        payload = record.data[eth.header_length :]
        if eth.ethertype == 0x0806:
            packet.arp = parse_arp(payload)
        elif eth.ethertype == 0x0800:
            packet.ip = ip = parse_ipv4(payload)
            if ip.total_length > record.original_length - eth.header_length:
                raise ParseError("IPv4 total length exceeds original wire payload")
            if len(payload) < ip.total_length:
                packet.truncated.append("captured IPv4 payload incomplete")
            if ip.fragmented:
                packet.unsupported = "IPv4 fragment (no reassembly)"
                return packet
            segment = payload[ip.header_length : ip.total_length]
            expected = ip.total_length - ip.header_length
            if ip.protocol == 6:
                packet.tcp = parse_tcp(segment, expected)
            elif ip.protocol == 17:
                packet.udp = udp = parse_udp(segment, expected)
                # mDNS/5353 and quoted packets are not ordinary DNS transactions.
                if 53 in (udp.src_port, udp.dst_port):
                    if len(udp.captured_payload) < udp.length - 8:
                        raise ParseError("captured DNS payload incomplete", truncated=True)
                    from .dns import parse_dns

                    packet.dns = parse_dns(udp.captured_payload)
            elif ip.protocol == 1:
                packet.icmp = parse_icmp(segment, expected)
            else:
                packet.unsupported = f"IPv4 protocol {ip.protocol}"
        else:
            packet.unsupported = f"EtherType 0x{eth.ethertype:04x}"
    except ParseError as exc:
        (packet.truncated if exc.truncated else packet.malformed).append(str(exc))
    return packet
