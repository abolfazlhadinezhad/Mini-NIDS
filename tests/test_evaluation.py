import csv
import json
from decimal import Decimal

import pytest

from mininids.evaluation import Reference, evaluate, load_references


def test_metrics_incident_vs_alert_semantics(tmp_path):
    path = tmp_path / "alerts.csv"
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, ["timestamp", "attack", "src", "dst"])
        writer.writeheader()
        for timestamp, attack in (
            (11, "Port Scan"),
            (12, "Port Scan"),
            (25, "Port Scan"),
            (11, "SYN Flood"),
        ):
            writer.writerow({"timestamp": timestamp, "attack": attack, "src": "a", "dst": "b"})
    refs = [
        Reference("a", "Port Scan", Decimal(10), Decimal(20)),
        Reference("b", "Port Scan", Decimal(30), Decimal(40)),
    ]
    result = evaluate(path, refs)["attacks"]
    assert result["Port Scan"]["true_alerts"] == 2
    assert result["Port Scan"]["false_alerts"] == 1
    assert result["Port Scan"]["recall_incident_level"] == 0.5
    assert result["Port Scan"]["precision_alert_level"] == pytest.approx(2 / 3)
    assert result["Port Scan"]["first_detection_delay_seconds"] == {"a": "1"}
    assert result["SYN Flood"]["false_alerts"] == 1
    assert result["SYN Flood"]["recall_incident_level"] is None
    assert result["ARP Spoofing"]["precision_alert_level"] is None


def test_references_validate(tmp_path):
    path = tmp_path / "ref.json"
    row = {"incident_id": "a", "attack": "Port Scan", "start": "10", "end": "20"}
    path.write_text(json.dumps([row]))
    assert load_references(path)[0].start == 10
    for rows in (
        [row, row],
        [{**row, "end": "0"}],
        [{**row, "start": "NaN"}],
        [row, {**row, "incident_id": "b"}],
    ):
        path.write_text(json.dumps(rows))
        with pytest.raises(ValueError):
            load_references(path)
