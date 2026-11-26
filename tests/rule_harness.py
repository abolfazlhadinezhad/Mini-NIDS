from importlib import import_module

from mininids.config import Config
from mininids.state import ARPTable, DNSTable, FlowTable
from tests.builders import CLIENT, GATEWAY, SERVER, dns, ethernet, ipv4, tcp, udp
from tests.test_protocols import packet


class RuleHarness:
    def __init__(self, names, **changes):
        self.config = Config(**changes)
        self.alerts = []
        self.flows = FlowTable(self.config)
        self.arps, self.dns = ARPTable(self.config), DNSTable(self.config)

        def emit(*args):
            self.alerts.append(args)

        classes = {"arp": "ARPRule", "scan": "ScanRule", "syn": "SYNRule", "dns": "DNSRule"}
        self.rules = {}
        for name in names:
            cls = getattr(import_module("mininids.rules." + name), classes[name])
            self.rules[name] = (
                cls(self.config, emit, self.arps) if name == "dns" else cls(self.config, emit)
            )

    def feed(self, data, now):
        p = packet(data)
        object.__setattr__(p.record, "timestamp_ns", int(now * 1e9))
        previous, requested = self.arps.observe(p, now)
        tx = self.dns.observe(p, now)
        event = self.flows.update(p, now)
        for name, rule in self.rules.items():
            if name == "arp":
                rule.process(p, now, previous, requested)
            elif name == "dns":
                rule.process(p, now, tx)
            else:
                rule.process(p, now, event)
        return p

    def ids(self):
        return {a[1] for a in self.alerts}


def scan_packet(port, flags=2, reverse=False, ack=0, seq=100):
    return ethernet(
        ipv4(
            tcp(
                sport=port if reverse else 40000,
                dport=40000 if reverse else port,
                flags=flags,
                seq=seq,
                ack=ack,
            ),
            src=SERVER if reverse else CLIENT,
            dst=CLIENT if reverse else SERVER,
        )
    )


def dns_packet(txid=1, response=False, src_mac=GATEWAY, address="203.0.113.5"):
    return ethernet(
        ipv4(
            udp(
                dns(txid=txid, response=response, address=address),
                sport=53 if response else 40000,
                dport=40000 if response else 53,
            ),
            proto=17,
            src=SERVER if response else CLIENT,
            dst=CLIENT if response else SERVER,
        ),
        src=src_mac,
    )
