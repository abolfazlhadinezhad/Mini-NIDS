from tests.builders import GATEWAY, ROGUE, arp, ethernet
from tests.rule_harness import RuleHarness, dns_packet


def test_large_answer_state_is_sampled_but_conflict_checks_complete_set():
    import struct

    from tests.builders import CLIENT, SERVER, dns, ip, ipv4, udp

    h = Harness()
    query = h.feed(dns_packet(999), 0)
    transaction = h.dns.table.get(h.dns.key(query), 0)
    for changed, timestamp in ((False, 0.1), (True, 0.2)):
        raw = bytearray(dns(txid=999))
        raw[2:4] = struct.pack("!H", 0x8180)
        raw[6:8] = struct.pack("!H", 20)
        for i in range(20):
            address = "198.51.100.99" if changed and i == 19 else f"203.0.113.{i + 1}"
            raw += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip(address)
        frame = ethernet(
            ipv4(udp(bytes(raw), sport=53, dport=40000), proto=17, src=SERVER, dst=CLIENT),
            src=GATEWAY,
        )
        h.feed(frame, timestamp)
    assert len(transaction.answers) == 8
    assert "DNS-1" in h.ids()  # Changed record was outside retained sample.


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


def test_id_collision_on_another_client_port_is_independent():
    from tests.builders import CLIENT, SERVER, dns, ipv4, udp

    h = Harness()
    for i in (1, 2):
        h.feed(dns_packet(i), i)
        h.feed(dns_packet(i, True), i + 0.1)
    h.feed(dns_packet(50), 3)
    wrong_port = ethernet(
        ipv4(
            udp(dns(txid=50, response=True, address="198.51.100.99"), sport=53, dport=40001),
            proto=17,
            src=SERVER,
            dst=CLIENT,
        ),
        src=ROGUE,
    )
    h.feed(wrong_port, 3.1)
    assert not h.alerts
