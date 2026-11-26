from ..bounded import BoundedTable, scope


class DNSRule:
    """Separate L2 ARP, cross-layer and DNS transaction conflict evidence."""

    def __init__(self, config, emit, arp_table):
        self.config, self.emit, self.arp_table = config, emit, arp_table
        self.resolver_macs = BoundedTable(
            config.max_mappings, config.arp_timeout, config.arp_timeout * 2
        )
        self.tables = [self.resolver_macs]

    def process(self, packet, now, tx):
        dns = packet.dns
        if dns is None or not dns.response or tx is None:
            return  # Unsolicited responses alone can mean asymmetric capture.
        ip, eth = packet.ip, packet.ethernet
        if packet.record.timestamp_ns < tx.timestamp_ns:
            return  # Negative RTT is not evidence of a race.
        prefix = scope(packet)
        canonical = tuple(sorted((r.name, r.type, r.cls, r.value) for r in dns.answers))
        evidence = {
            "transaction_id": dns.transaction_id,
            "questions": [q.name for q in dns.questions],
            "response_mac": eth.src,
            "resolver_ip": ip.src,
            "client_port": packet.udp.dst_port,
            "answers": [r.value for r in dns.answers],
            "ttls": [r.ttl for r in dns.answers],
            "rcode": dns.rcode,
            "ip_ttl": ip.ttl,
            "rtt_seconds": (packet.record.timestamp_ns - tx.timestamp_ns) / 1e9,
        }
        key = (prefix, ip.dst, ip.src, dns.questions[0].name)
        # DNS-1: application conflict, only exact same outstanding/recent transaction.
        if tx.answers is not None and tx.answers != canonical and not dns.truncated:
            self.emit(
                packet,
                "DNS-1",
                "DNS Spoofing",
                ip.src,
                ip.dst,
                {
                    **evidence,
                    "previous_answers": list(tx.answers),
                    "previous_mac": tx.response_mac,
                    "response_gap_seconds": (packet.record.timestamp_ns - tx.response_ns) / 1e9,
                },
                key,
            )
        # DNS-2: L2 claim learned from stable ARP, exact resolver IP only.
        mapping = self.arp_table.mappings.get((prefix, ip.src), now, touch=False)
        if (
            mapping
            and mapping.observations >= self.config.arp_stable_observations
            and mapping.mac != eth.src
        ):
            self.emit(
                packet,
                "DNS-2",
                "DNS Spoofing",
                ip.src,
                ip.dst,
                {**evidence, "arp_mac": mapping.mac, "arp_observations": mapping.observations},
                key,
            )
        # DNS-3: cross-layer source-MAC changes for a correlated resolver IP.
        known = self.resolver_macs.get((prefix, ip.src), now)
        if known and known[0] != eth.src and known[1] >= 2:
            self.emit(
                packet,
                "DNS-3",
                "DNS Spoofing",
                ip.src,
                ip.dst,
                {**evidence, "learned_resolver_mac": known[0], "learned_observations": known[1]},
                key,
            )
        elif known is None or known[0] == eth.src:
            self.resolver_macs.put((prefix, ip.src), (eth.src, known[1] + 1 if known else 1), now)
        if not dns.truncated and tx.answers is None:
            tx.answers, tx.response_mac, tx.response_ns = (
                canonical,
                eth.src,
                packet.record.timestamp_ns,
            )
