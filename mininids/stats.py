"""Bounded capture summary and streaming sparse per-second traffic series."""

from collections import Counter

from .protocols import FLAG_NAMES, SYN


class LimitedCounter:
    def __init__(self, capacity=4096):
        self.capacity, self.counts, self.other = capacity, Counter(), 0

    def add(self, key):
        if key in self.counts or len(self.counts) < self.capacity:
            self.counts[key] += 1
        else:
            self.other += 1

    def summary(self):
        return {
            "top": self.counts.most_common(20),
            "untracked_observations": self.other,
            "key_limit": self.capacity,
        }


class Statistics:
    def __init__(self, outputs):
        self.outputs = outputs
        self.counts, self.protocols, self.flags, self.sizes = (
            Counter(),
            Counter(),
            Counter(),
            Counter(),
        )
        self.sources, self.destinations = LimitedCounter(), LimitedCounter()
        self.first_ns = self.last_ns = None
        for name in (
            "packets",
            "malformed_packets",
            "truncated_packets",
            "unsupported_packets",
            "dns_queries",
            "dns_responses",
            "ipv4_fragments",
            "backward_timestamp_packets",
        ):
            self.counts[name] = 0
        self.minimum_ns = self.maximum_ns = None
        self.current_second = None
        self.bucket = Counter()
        self.peak_pps = 0
        self.wire_sum = self.capture_sum = 0
        self.min_size = None
        self.max_size = 0

    def flush_bucket(self):
        if self.current_second is not None:
            self.outputs.rates.writerow(
                {
                    "epoch_second": self.current_second,
                    **{key: self.bucket[key] for key in ("packets", "wire_bytes", "syn_packets")},
                }
            )
            self.peak_pps = max(self.peak_pps, self.bucket["packets"])
            self.bucket.clear()

    def observe(self, packet, watermark_ns):
        record = packet.record
        ns, size = record.timestamp_ns, record.original_length
        if self.first_ns is None:
            self.first_ns = self.minimum_ns = self.maximum_ns = ns
        if self.last_ns is not None and ns < self.last_ns:
            self.counts["backward_timestamp_packets"] += 1
        self.last_ns = ns
        self.minimum_ns, self.maximum_ns = min(ns, self.minimum_ns), max(ns, self.maximum_ns)
        self.counts["packets"] += 1
        self.wire_sum += size
        self.capture_sum += len(record.data)
        self.min_size = min(self.min_size if self.min_size is not None else size, size)
        self.max_size = max(self.max_size, size)
        self.sizes[
            next(
                (
                    label
                    for bound, label in (
                        (64, "0-64"),
                        (128, "65-128"),
                        (512, "129-512"),
                        (1518, "513-1518"),
                    )
                    if size <= bound
                ),
                ">1518",
            )
        ] += 1
        self.counts["malformed_packets"] += bool(packet.malformed)
        self.counts["truncated_packets"] += bool(packet.truncated)
        self.counts["unsupported_packets"] += bool(packet.unsupported)
        for name in ("ethernet", "arp", "ip", "tcp", "udp", "icmp", "dns"):
            if getattr(packet, name) is not None:
                self.protocols[name] += 1
        if packet.ip:
            self.sources.add(packet.ip.src)
            self.destinations.add(packet.ip.dst)
            self.counts["ipv4_fragments"] += packet.ip.fragmented
        if packet.tcp:
            for flag, name in FLAG_NAMES.items():
                self.flags[name] += bool(packet.tcp.flags & flag)
        if packet.dns:
            self.counts["dns_responses" if packet.dns.response else "dns_queries"] += 1
        second = watermark_ns // 1_000_000_000
        if self.current_second != second:
            self.flush_bucket()
            self.current_second = second
        self.bucket["packets"] += 1
        self.bucket["wire_bytes"] += size
        self.bucket["syn_packets"] += bool(packet.tcp and packet.tcp.flags & SYN)

    def summary(self):
        self.flush_bucket()
        self.current_second = None
        return {
            **self.counts,
            "first_timestamp_ns": self.first_ns,
            "last_timestamp_ns": self.last_ns,
            "minimum_timestamp_ns": self.minimum_ns,
            "maximum_timestamp_ns": self.maximum_ns,
            "duration_seconds": (
                (self.maximum_ns - self.minimum_ns) / 1e9 if self.minimum_ns is not None else 0
            ),
            "protocol_hierarchy_counts": dict(self.protocols),
            "tcp_flags": dict(self.flags),
            "packet_size_histogram": dict(self.sizes),
            "wire_bytes": self.wire_sum,
            "captured_bytes": self.capture_sum,
            "minimum_wire_size": self.min_size,
            "maximum_wire_size": self.max_size,
            "mean_wire_size": self.wire_sum / max(1, self.counts["packets"]),
            "top_sources": self.sources.summary(),
            "top_destinations": self.destinations.summary(),
            "peak_packets_per_watermark_second": self.peak_pps,
        }
