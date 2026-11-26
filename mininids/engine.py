"""Shared single-pass pipeline; input and output adapters own file handles."""

from .config import Config
from .output import AlertSink
from .protocols import parse_packet
from .rules.arp import ARPRule
from .rules.dns import DNSRule
from .rules.scan import ScanRule
from .rules.syn import SYNRule
from .state import ARPTable, DNSTable, FlowTable
from .stats import Statistics


class Engine:
    def __init__(self, outputs, config=None):
        self.config = config or Config()
        self.outputs = outputs
        self.stats = Statistics(outputs)
        self.alerts = AlertSink(self.config, outputs)
        self.flows = FlowTable(self.config, outputs.flow)
        self.arps, self.dns = ARPTable(self.config), DNSTable(self.config)
        self.arp_rule = ARPRule(self.config, self.alerts.emit)
        self.scan_rule = ScanRule(self.config, self.alerts.emit)
        self.syn_rule = SYNRule(self.config, self.alerts.emit)
        self.dns_rule = DNSRule(self.config, self.alerts.emit, self.arps)
        self.tables = {
            "flows": self.flows.table,
            "arp_mappings": self.arps.mappings,
            "arp_requests": self.arps.requests,
            "dns_transactions": self.dns.table,
            "arp_conflicts": self.arp_rule.conflicts,
            "scan_windows": self.scan_rule.probes,
            "syn_windows": self.syn_rule.destinations,
            "resolver_macs": self.dns_rule.resolver_macs,
            "alert_aggregation": self.alerts.pending,
        }
        self.watermark_ns = None
        self.last_cleanup = None
        self.closed = False

    def process(self, record):
        if self.closed:
            raise RuntimeError("engine already finalized")
        self.watermark_ns = max(record.timestamp_ns, self.watermark_ns or record.timestamp_ns)
        now = self.watermark_ns / 1e9
        self.alerts.now = now
        if self.last_cleanup is None or now - self.last_cleanup >= 1:
            for table in self.tables.values():
                table.expire(now)
            self.last_cleanup = now
        packet = parse_packet(record)
        self.stats.observe(packet, self.watermark_ns)
        if not packet.malformed:
            event = self.flows.update(packet, now)
            previous, requested = self.arps.observe(packet, now)
            tx = self.dns.observe(packet, now)
            self.arp_rule.process(packet, now, previous, requested)
            self.scan_rule.process(packet, now, event)
            self.syn_rule.process(packet, now, event)
            self.dns_rule.process(packet, now, tx)
            if packet.dns:
                self.outputs.dns_packet(packet, tx)
        return packet

    def finish(self):
        if self.closed:
            raise RuntimeError("engine already finalized")
        self.closed = True
        for table in self.tables.values():
            table.close()
        summary = self.stats.summary()
        summary["alerts_emitted"] = dict(self.alerts.emitted)
        summary["rule_matches"] = dict(self.alerts.matches)
        summary["scan_item_capacity_evictions"] = self.scan_rule.item_evictions
        summary["state_tables"] = {
            name: {
                "capacity": table.capacity,
                "peak_entries": table.peak,
                "removals": dict(table.removals),
            }
            for name, table in self.tables.items()
        }
        return summary
