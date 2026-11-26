from mininids.capture import Record
from mininids.config import Config
from mininids.engine import Engine
from mininids.output import Outputs
from mininids.rules.common import Counts, Items
from tests.builders import ethernet, ipv4, tcp


def test_all_engine_tables_stay_within_caps(tmp_path):
    config = Config(
        max_flows=8,
        max_mappings=8,
        max_queries=8,
        max_rule_keys=4,
        max_window_items=8,
        scan_ports=4,
        syn_rate=0.1,
    )
    outputs = Outputs(tmp_path / "out")
    engine = Engine(outputs, config)
    for i in range(2000):
        raw = ethernet(
            ipv4(tcp(sport=1000 + i, dport=80 + i % 50), src=f"10.0.{i // 250}.{i % 250 + 1}")
        )
        engine.process(Record(1_000_000_000 + i * 10000, raw, len(raw)))
        for table in engine.tables.values():
            assert len(table) <= table.capacity
    summary = engine.finish()
    outputs.close()
    assert summary["state_tables"]["flows"]["removals"]["capacity"] == 1992
    assert summary["state_tables"]["scan_windows"]["peak_entries"] <= 4


def test_window_data_is_bounded_and_clears_after_gap():
    counts = Counts(10)
    for i in range(10000):
        counts.add(i / 100, "syn")
        assert len(counts.buckets) <= 65
    assert counts.add(1e9, "syn")["syn"] == 1
    items = Items(8, 10)
    for i in range(100):
        items.put(i, True, 0)
    assert len(items.items) == 8 and items.evictions == 92
    items.prune(10)
    assert not items.items
