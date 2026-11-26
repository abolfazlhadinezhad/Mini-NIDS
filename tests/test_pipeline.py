import csv
import json

from mininids.capture import Record
from mininids.cli import main
from mininids.config import Config
from mininids.engine import Engine
from mininids.output import Outputs
from tests.builders import ethernet, ipv4, pcap, tcp


def test_cli_round_trip_and_no_overwrite(tmp_path):
    source = tmp_path / "capture.pcap"
    frame = ethernet(ipv4(tcp()))
    source.write_bytes(pcap([(1_000_000_000, frame, None), (2_000_000_000, frame, None)]))
    out = tmp_path / "results"
    assert main(["--pcap", str(source), "--out", str(out)]) == 0
    stats = json.loads((out / "stats.json").read_text())
    assert stats["packets"] == 2 and stats["duration_seconds"] == 1
    assert stats["tcp_flags"]["SYN"] == 2
    assert stats["state_tables"]["flows"]["peak_entries"] == 1
    flow = json.loads((out / "flows.jsonl").read_text())
    assert flow["packets"] == [2, 0]
    assert flow["retransmissions"] == 1
    assert main(["--pcap", str(source), "--out", str(out)]) == 2


def test_corrupt_tail_marks_partial_run(tmp_path):
    source = tmp_path / "bad.pcap"
    source.write_bytes(pcap([(0, ethernet(ipv4(tcp())), None)]) + b"x")
    out = tmp_path / "out"
    assert main(["--pcap", str(source), "--out", str(out)]) == 2
    assert json.loads((out / "run.json").read_text())["status"] == "failed"
    assert json.loads((out / "stats.json").read_text())["packets"] == 1


def test_empty_capture_statistics(tmp_path):
    source = tmp_path / "empty.pcap"
    source.write_bytes(pcap([]))
    out = tmp_path / "empty"
    assert main(["--pcap", str(source), "--out", str(out)]) == 0
    assert json.loads((out / "stats.json").read_text())["packets"] == 0


def test_first_alert_immediate_and_aggregation_exact(tmp_path):
    outputs = Outputs(tmp_path / "out")
    engine = Engine(outputs, Config(scan_ports=2))
    for i in range(10):
        engine.process(Record(int(i * 1e8), ethernet(ipv4(tcp(dport=80 + i))), 54))
        if i == 1:
            with (tmp_path / "out" / "alerts.csv").open() as f:
                assert len(list(csv.DictReader(f))) == 1  # Before finish().
    result = engine.finish()
    outputs.close()
    assert result["alerts_emitted"] == {"SCAN-TCP": 1}
    assert result["rule_matches"] == {"SCAN-TCP": 9}
    with (tmp_path / "out" / "alert_aggregates.csv").open() as f:
        assert list(csv.DictReader(f))[0]["suppressed"] == "8"


def test_backward_timestamp_and_large_gap(tmp_path):
    outputs = Outputs(tmp_path / "out")
    engine = Engine(outputs)
    for ns in (3_000_000_000, 1_000_000_000, 1_000_000_000_000):
        engine.process(Record(ns, ethernet(ipv4(tcp())), 54))
    summary = engine.finish()
    outputs.close()
    assert summary["backward_timestamp_packets"] == 1
    assert summary["duration_seconds"] == 999
    assert summary["state_tables"]["flows"]["removals"]["expired"] == 1
