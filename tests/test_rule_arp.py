from tests.builders import CLIENT, GATEWAY, ROGUE, SERVER, arp, ethernet
from tests.rule_harness import RuleHarness


def Harness(**changes):
    return RuleHarness(("arp",), **changes)


def test_arp_context_and_repetition():
    h = Harness()
    for t in (0, 1):
        h.feed(ethernet(arp(), 0x0806, src=GATEWAY), t)
    for t in (2, 3):
        h.feed(ethernet(arp(sender_mac=ROGUE), 0x0806, src=ROGUE), t)
    assert not h.alerts
    h.feed(ethernet(arp(sender_mac=ROGUE), 0x0806, src=ROGUE), 4)
    assert h.ids() == {"ARP-1"}
    assert h.alerts[0][5]["incumbent_mac"] == GATEWAY


def test_gratuitous_and_requested_arp_not_attack():
    h = Harness()
    for t in range(3):
        h.feed(ethernet(arp(), 0x0806), t)
    for t in range(3, 10):
        h.feed(ethernet(arp(sender_mac=ROGUE, target_ip=SERVER), 0x0806), t)
    h.feed(ethernet(arp(sender_ip=CLIENT, target_ip=SERVER, op=1), 0x0806), 10)
    for t in range(11, 15):
        h.feed(ethernet(arp(sender_mac=ROGUE), 0x0806), t)
    assert not h.alerts
