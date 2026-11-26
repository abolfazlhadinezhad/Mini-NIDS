from tests.builders import GATEWAY, ROGUE, arp, ethernet
from tests.rule_harness import RuleHarness, dns_packet


def Harness(**changes):
    return RuleHarness(("dns",), **changes)


def test_three_dns_rules_with_exact_correlation():
    h = Harness()
    for t in (0, 0.1):
        h.feed(ethernet(arp(), 0x0806, src=GATEWAY), t)
    for txid, t in ((1, 1), (2, 2)):
        h.feed(dns_packet(txid), t)
        h.feed(dns_packet(txid, True), t + 0.1)
    h.feed(dns_packet(2, True, ROGUE, "198.51.100.99"), 2.2)
    assert {"DNS-1", "DNS-2", "DNS-3"} <= h.ids()


def test_dns_duplicates_new_transactions_and_alternate_resolvers_are_benign():
    h = Harness()
    for i in range(10):
        h.feed(dns_packet(i), i)
        h.feed(dns_packet(i, True, address=f"203.0.113.{i + 1}"), i + 0.1)
        h.feed(dns_packet(i, True, address=f"203.0.113.{i + 1}"), i + 0.2)
    h.feed(dns_packet(500, True, ROGUE), 9.5)  # Not correlated.
    assert not h.alerts
