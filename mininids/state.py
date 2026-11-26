"""Independent flow/TCP, ARP and DNS tables."""

from collections import Counter
from dataclasses import dataclass, field

from .bounded import BoundedTable, scope
from .protocols import ACK, FIN, FLAG_NAMES, RST, SYN


@dataclass(slots=True)
class Flow:
    src: str
    dst: str
    src_port: int
    dst_port: int
    protocol: int
    vlan: tuple
    first_ns: int
    last_ns: int
    packets: list[int] = field(default_factory=lambda: [0, 0])
    wire_bytes: list[int] = field(default_factory=lambda: [0, 0])
    captured_bytes: list[int] = field(default_factory=lambda: [0, 0])
    tcp_flags: Counter = field(default_factory=Counter)
    state: str = "INCOMPLETE"
    syn_seq: int | None = None
    synack_seq: int | None = None
    syn_timestamp_ns: int | None = None
    synack_timestamp_ns: int | None = None
    established_timestamp_ns: int | None = None
    close_timestamp_ns: int | None = None
    initiator: int | None = None
    fin_directions: int = 0
    retransmissions: int = 0
    last_segment: list = field(default_factory=lambda: [None, None])


@dataclass(slots=True)
class FlowEvent:
    flow: Flow
    direction: int
    syn_new: bool = False
    synack_new: bool = False
    established_new: bool = False
    reset_new: bool = False


class FlowTable:
    def __init__(self, config, on_remove=None):
        self.table = BoundedTable(
            config.max_flows, config.idle_timeout, config.active_timeout, on_remove
        )

    def update(self, packet, now):
        ip = packet.ip
        if ip is None or ip.fragmented or packet.malformed:
            return None
        transport = packet.tcp or packet.udp
        sport = transport.src_port if transport else 0
        dport = transport.dst_port if transport else 0
        endpoints = ((ip.src, sport), (ip.dst, dport))
        ordered = tuple(sorted(endpoints))
        key = (scope(packet), ip.protocol, ordered)
        flow = self.table.get(key, now)
        if (
            flow is not None
            and packet.tcp is not None
            and packet.tcp.flags & SYN
            and not packet.tcp.flags & ACK
            and flow.syn_seq is not None
            and flow.syn_seq != packet.tcp.sequence
        ):
            self.table.remove(key, "tuple_reuse")
            flow = None
        if flow is None:
            flow = self.table.put(
                key,
                Flow(
                    ip.src,
                    ip.dst,
                    sport,
                    dport,
                    ip.protocol,
                    scope(packet),
                    packet.record.timestamp_ns,
                    packet.record.timestamp_ns,
                ),
                now,
            )
        direction = int((ip.src, sport) != (flow.src, flow.src_port))
        flow.last_ns = packet.record.timestamp_ns
        flow.packets[direction] += 1
        flow.wire_bytes[direction] += packet.record.original_length
        flow.captured_bytes[direction] += len(packet.record.data)
        event = FlowEvent(flow, direction)
        tcp = packet.tcp
        if tcp:
            for mask, name in FLAG_NAMES.items():
                if tcp.flags & mask:
                    flow.tcp_flags[name] += 1
            signature = (tcp.sequence, tcp.acknowledgment, tcp.flags, tcp.payload_length)
            if signature == flow.last_segment[direction] and (
                tcp.flags & SYN or tcp.payload_length
            ):
                flow.retransmissions += 1
            flow.last_segment[direction] = signature
            if tcp.flags & RST:
                event.reset_new = flow.state != "RESET"
                flow.state = "RESET"
                flow.close_timestamp_ns = packet.record.timestamp_ns
            elif tcp.flags & SYN and not tcp.flags & ACK:
                if flow.syn_seq is None or (
                    flow.state in ("FINISHED", "RESET") and flow.syn_seq != tcp.sequence
                ):
                    flow.syn_seq = tcp.sequence
                    flow.synack_seq = None
                    flow.initiator = direction
                    flow.state = "SYN_SENT"
                    flow.syn_timestamp_ns = packet.record.timestamp_ns
                    flow.fin_directions = 0
                    event.syn_new = True
            elif tcp.flags & SYN and tcp.flags & ACK:
                if (
                    flow.state == "SYN_SENT"
                    and direction != flow.initiator
                    and tcp.acknowledgment == (flow.syn_seq + 1) % (1 << 32)
                ):
                    flow.synack_seq = tcp.sequence
                    flow.state = "SYN_ACK_RECEIVED"
                    flow.synack_timestamp_ns = packet.record.timestamp_ns
                    event.synack_new = True
            elif (
                tcp.flags & ACK
                and flow.state == "SYN_ACK_RECEIVED"
                and direction == flow.initiator
                and tcp.sequence == (flow.syn_seq + 1) % (1 << 32)
                and tcp.acknowledgment == (flow.synack_seq + 1) % (1 << 32)
            ):
                flow.state = "ESTABLISHED"
                flow.established_timestamp_ns = packet.record.timestamp_ns
                event.established_new = True
            if tcp.flags & FIN and flow.state != "RESET":
                flow.fin_directions |= 1 << direction
                if flow.fin_directions == 3:
                    flow.state = "FINISHED"
                    flow.close_timestamp_ns = packet.record.timestamp_ns
        return event


@dataclass(slots=True)
class Mapping:
    mac: str
    first_ns: int
    observations: int = 1


class ARPTable:
    def __init__(self, config):
        self.mappings = BoundedTable(
            config.max_mappings, config.arp_timeout, config.arp_timeout * 2
        )
        self.requests = BoundedTable(config.max_mappings, config.dns_timeout, config.dns_timeout)

    def observe(self, packet, now):
        arp = packet.arp
        if not arp:
            return None, False
        prefix = scope(packet)
        previous = self.mappings.get((prefix, arp.sender_ip), now)
        requested = False
        if arp.operation == 1:
            self.requests.put((prefix, arp.sender_ip, arp.target_ip), True, now)
        else:
            requested = self.requests.get((prefix, arp.target_ip, arp.sender_ip), now) is not None
        # Preserve a stable incumbent against untrusted conflicting announcements.
        if arp.sender_ip != "0.0.0.0" and arp.sender_mac != "00:00:00:00:00:00":
            if previous is None:
                self.mappings.put(
                    (prefix, arp.sender_ip),
                    Mapping(arp.sender_mac, packet.record.timestamp_ns),
                    now,
                )
            elif previous.mac == arp.sender_mac:
                previous.observations += 1
        return previous, requested


@dataclass(slots=True)
class Transaction:
    timestamp_ns: int
    answers: tuple | None = None
    response_mac: str | None = None
    response_ns: int | None = None


class DNSTable:
    def __init__(self, config):
        self.table = BoundedTable(config.max_queries, config.dns_timeout, config.dns_timeout)

    @staticmethod
    def key(packet):
        dns, ip, udp = packet.dns, packet.ip, packet.udp
        if dns.response:
            client, cp, server, sp = ip.dst, udp.dst_port, ip.src, udp.src_port
        else:
            client, cp, server, sp = ip.src, udp.src_port, ip.dst, udp.dst_port
        return (
            scope(packet),
            client,
            cp,
            server,
            sp,
            dns.transaction_id,
            tuple((q.name, q.type, q.cls) for q in dns.questions),
        )

    def observe(self, packet, now):
        if packet.dns is None or not packet.dns.questions:
            return None
        key = self.key(packet)
        existing = self.table.get(key, now, touch=False)
        if not packet.dns.response:
            if existing is None or existing.answers is not None:
                if existing is not None:
                    self.table.remove(key, "new_query")
                return self.table.put(key, Transaction(packet.record.timestamp_ns), now)
        return existing
