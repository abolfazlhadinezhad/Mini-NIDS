from ..bounded import scope
from .common import Counts, table


class ARPRule:
    """Repeated unsolicited conflict against an observed stable incumbent."""

    def __init__(self, config, emit):
        self.config, self.emit = config, emit
        self.conflicts = table(config)
        self.tables = [self.conflicts]

    def process(self, packet, now, previous, requested):
        arp = packet.arp
        if not arp or arp.operation != 2 or previous is None:
            return
        if arp.sender_mac == previous.mac or arp.sender_ip == arp.target_ip or requested:
            return  # Gratuitous and solicited replies alone are not malicious.
        if previous.observations < self.config.arp_stable_observations:
            return
        key = (scope(packet), arp.sender_ip, arp.sender_mac)
        counts = self.conflicts.get(key, now)
        if counts is None:
            counts = self.conflicts.put(key, Counts(self.config.window_seconds), now)
        count = counts.add(now, "conflict")["conflict"]
        if count >= self.config.arp_conflicts:
            self.emit(
                packet,
                "ARP-1",
                "ARP Spoofing",
                arp.sender_mac,
                arp.target_ip,
                {
                    "claimed_ip": arp.sender_ip,
                    "incumbent_mac": previous.mac,
                    "claimant_mac": arp.sender_mac,
                    "incumbent_observations": previous.observations,
                    "unsolicited_conflicts": count,
                    "threshold": self.config.arp_conflicts,
                    "window_seconds": self.config.window_seconds,
                    "ethernet_source_matches_claim": packet.ethernet.src == arp.sender_mac,
                },
                key,
            )
