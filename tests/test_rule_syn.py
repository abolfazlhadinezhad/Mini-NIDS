from tests.builders import CLIENT, SERVER, ethernet, ipv4, tcp
from tests.rule_harness import RuleHarness


def Harness(**changes):
    return RuleHarness(("syn",), **changes)


def test_syn_flood_destination_aggregation_and_completed_baseline():
    h = Harness(syn_rate=1, scan_ports=100)
    for i in range(10):
        h.feed(ethernet(ipv4(tcp(sport=1000 + i), src=f"10.0.1.{i + 1}")), i / 10)
    assert "SYN-1" in h.ids()
    h = Harness(syn_rate=1, scan_ports=100)
    for i in range(12):
        for offset, data in enumerate(
            (
                ethernet(ipv4(tcp(sport=1000 + i))),
                ethernet(
                    ipv4(
                        tcp(sport=80, dport=1000 + i, flags=0x12, seq=300, ack=101),
                        src=SERVER,
                        dst=CLIENT,
                    )
                ),
                ethernet(ipv4(tcp(sport=1000 + i, flags=0x10, seq=101, ack=301))),
            )
        ):
            h.feed(data, i / 2 + offset / 100)
    assert "SYN-1" not in h.ids()
