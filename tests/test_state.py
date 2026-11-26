from mininids.bounded import BoundedTable
from mininids.config import Config
from mininids.state import ARPTable, DNSTable, FlowTable
from tests.builders import CLIENT, SERVER, arp, dns, ethernet, ipv4, tcp, udp
from tests.test_protocols import packet


def seg(flags, reverse=False, seq=100, ack=0):
    return packet(
        ethernet(
            ipv4(
                tcp(
                    sport=80 if reverse else 40000,
                    dport=40000 if reverse else 80,
                    flags=flags,
                    seq=seq,
                    ack=ack,
                ),
                src=SERVER if reverse else CLIENT,
                dst=CLIENT if reverse else SERVER,
            )
        )
    )


def test_handshake_checks_sequence_and_direction():
    table = FlowTable(Config())
    assert table.update(seg(2), 0).syn_new
    assert not table.update(seg(2), 0.1).syn_new
    event = table.update(seg(0x12, True, 300, 0), 0.2)
    assert event.flow.state == "SYN_SENT"
    assert table.update(seg(0x12, True, 300, 101), 0.3).synack_new
    assert table.update(seg(0x10, False, 101, 301), 0.4).established_new
    table.update(seg(0x11), 0.5)
    flow = table.update(seg(0x11, True), 0.6).flow
    assert flow.state == "FINISHED"
    assert len(table.table) == 1
    assert flow.packets == [4, 3]
    assert flow.retransmissions == 1
    assert flow.syn_timestamp_ns == 123
    assert flow.established_timestamp_ns == 123


def test_midstream_is_incomplete_and_reset():
    table = FlowTable(Config())
    assert table.update(seg(0x10), 0).flow.state == "INCOMPLETE"
    assert table.update(seg(4, True), 1).flow.state == "RESET"


def test_tuple_reuse_exports_previous_connection():
    removed = []
    table = FlowTable(Config(), lambda flow, reason: removed.append((flow, reason)))
    first = table.update(seg(2), 0).flow
    event = table.update(seg(2, seq=200), 1)
    assert event.syn_new and event.flow is not first
    assert removed == [(first, "tuple_reuse")]
    assert event.flow.packets == [1, 0]


def test_vlan_priority_does_not_split_flow():
    table = FlowTable(Config())
    for priority in (0, 3, 7):
        raw = ethernet(ipv4(tcp()), vlan=(priority << 13) | 7)
        table.update(packet(raw), 0)
    assert len(table.table) == 1


def test_truncated_transport_does_not_invent_ports():
    table = FlowTable(Config())
    raw = ethernet(ipv4(tcp()))
    truncated = packet(raw[:40], len(raw))
    assert truncated.tcp is None
    assert table.update(truncated, 0) is None
    assert len(table.table) == 0


def test_expiry_and_capacity_export():
    removed = []
    table = BoundedTable(2, 5, 8, lambda value, reason: removed.append((value, reason)))
    table.put("a", 1, 0)
    table.put("b", 2, 1)
    assert table.get("a", 2) == 1
    table.put("c", 3, 3)
    assert removed == [(2, "capacity")]
    table.get("a", 7)
    assert table.get("a", 8) is None  # Active timeout despite recent touch.
    table.expire(1000)
    assert len(table) == 0 and table.peak == 2


def test_arp_context():
    table = ARPTable(Config())
    request = packet(ethernet(arp(sender_ip=CLIENT, target_ip=SERVER, op=1), 0x0806))
    table.observe(request, 0)
    response = packet(ethernet(arp(), 0x0806))
    old, solicited = table.observe(response, 1)
    assert old is None and solicited
    old, _ = table.observe(response, 2)
    assert old.observations == 2
    assert not table.observe(response, 12)[1]


def test_dns_query_key_and_expiry():
    table = DNSTable(Config())
    query = packet(ethernet(ipv4(udp(dns()), proto=17)))
    response = packet(
        ethernet(
            ipv4(udp(dns(response=True), sport=53, dport=40000), proto=17, src=SERVER, dst=CLIENT)
        )
    )
    tx = table.observe(query, 0)
    assert isinstance(table.key(query)[-1], bytes)
    assert len(table.key(query)[-1]) == 32
    assert table.observe(response, 1) is tx
    assert table.observe(response, 11) is None


def test_config_rejects_bad_values(tmp_path):
    import pytest

    for kwargs in (
        {"scan_ports": 0},
        {"max_flows": 1.5},
        {"syn_rate": float("nan")},
        {"syn_incomplete_ratio": 2},
        {"max_queries": True},
    ):
        with pytest.raises(ValueError):
            Config(**kwargs)
    path = tmp_path / "bad.json"
    path.write_text('{"unknown": 1}')
    with pytest.raises(ValueError, match="unknown"):
        Config.from_file(path)
