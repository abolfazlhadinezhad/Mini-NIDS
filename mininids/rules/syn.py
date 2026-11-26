from ..bounded import scope
from .common import Counts, table


class SYNRule:
    """Aggregate by destination IP, not spoofable/distributed source identity."""

    def __init__(self, config, emit):
        self.config, self.emit = config, emit
        self.destinations = table(config)
        self.tables = [self.destinations]

    def process(self, packet, now, event):
        if not event or event.flow.initiator is None:
            return
        flow = event.flow
        victim = flow.dst if flow.initiator == 0 else flow.src
        key = (scope(packet), victim)
        counts = self.destinations.get(key, now)
        if counts is None:
            counts = self.destinations.put(key, Counts(self.config.window_seconds), now)
        name = (
            "syn"
            if event.syn_new
            else "synack"
            if event.synack_new
            else "complete"
            if event.established_new
            else "reset"
            if event.reset_new
            else None
        )
        if name is None:
            return
        metrics = counts.add(now, name)
        syns = metrics["syn"]
        rate = syns / self.config.window_seconds
        incomplete = max(0, syns - metrics["complete"]) / max(1, syns)
        if rate >= self.config.syn_rate and incomplete >= self.config.syn_incomplete_ratio:
            self.emit(
                packet,
                "SYN-1",
                "SYN Flood",
                "multiple-or-unverified",
                victim,
                {
                    "syn_count": syns,
                    "syn_rate": rate,
                    "completed_handshakes": metrics["complete"],
                    "synack_count": metrics["synack"],
                    "reset_count": metrics["reset"],
                    "incomplete_ratio": incomplete,
                    "rate_threshold": self.config.syn_rate,
                    "ratio_threshold": self.config.syn_incomplete_ratio,
                    "window_seconds": self.config.window_seconds,
                    "current_source": packet.ip.src,
                    "current_destination_port": packet.tcp.dst_port,
                    "tcp_flags": packet.tcp.flags,
                    "payload_length": packet.tcp.payload_length,
                    "wire_length": packet.record.original_length,
                },
                key,
            )
