from tests.builders import CLIENT, SERVER, ethernet, ipv4, udp
from tests.rule_harness import RuleHarness, scan_packet


def Harness(**changes):
    return RuleHarness(("scan",), **changes)


def test_vertical_tcp_scan_retransmissions_and_expiry():
    h = Harness(scan_ports=3)
    for i in range(100):
        h.feed(scan_packet(80), i / 100)
    assert not h.alerts
    h.feed(scan_packet(81), 2)
    h.feed(scan_packet(82), 3)
    assert "SCAN-TCP" in h.ids()
    h.alerts.clear()
    h.feed(scan_packet(83), 100)
    assert not h.alerts


def test_open_port_syn_vs_connect_classification():
    for connect, rule in ((False, "SCAN-1"), (True, "SCAN-2")):
        h = Harness(scan_ports=3)
        for i, port in enumerate(range(80, 83)):
            h.feed(scan_packet(port), i)
            h.feed(scan_packet(port, 0x12, True, ack=101, seq=300), i + 0.1)
            h.feed(scan_packet(port, 0x10 if connect else 4, ack=301, seq=101), i + 0.2)
        assert rule in h.ids()


def test_udp_scan_icmp_correlates_original_probe():
    h = Harness(scan_ports=3)
    for i, port in enumerate(range(100, 103)):
        inner = ipv4(udp(b"", dport=port), proto=17)
        h.feed(ethernet(inner), i)
        h.feed(
            ethernet(ipv4(b"\x03\x03\0\0" + b"\0" * 4 + inner, proto=1, src=SERVER, dst=CLIENT)),
            i + 0.1,
        )
    assert "SCAN-3" in h.ids()
