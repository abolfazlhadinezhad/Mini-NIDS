"""Analyst-defined incident intervals, independent of detector thresholds."""

import argparse
import csv
import json
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path

ATTACKS = ("ARP Spoofing", "Port Scan", "SYN Flood", "DNS Spoofing")


@dataclass(frozen=True)
class Reference:
    incident_id: str
    attack: str
    start: Decimal
    end: Decimal
    src: str | None = None
    dst: str | None = None
    evidence: str = ""


def load_references(path):
    with open(path, encoding="utf-8") as stream:
        raw = json.load(stream)
    if not isinstance(raw, list):
        raise ValueError("reference must be an array of incident intervals")
    refs, seen = [], set()
    for row in raw:
        ref = Reference(
            str(row["incident_id"]),
            row["attack"],
            Decimal(str(row["start"])),
            Decimal(str(row["end"])),
            row.get("src"),
            row.get("dst"),
            row.get("evidence", ""),
        )
        if ref.incident_id in seen:
            raise ValueError("duplicate incident_id")
        if (
            ref.attack not in ATTACKS
            or not ref.start.is_finite()
            or not ref.end.is_finite()
            or ref.end < ref.start
        ):
            raise ValueError("invalid reference attack or interval")
        seen.add(ref.incident_id)
        refs.append(ref)
    for i, a in enumerate(refs):
        for b in refs[i + 1 :]:
            if (
                a.attack == b.attack
                and a.src == b.src
                and a.dst == b.dst
                and a.start <= b.end
                and b.start <= a.end
            ):
                raise ValueError("overlapping reference intervals for the same participants")
    return refs


def evaluate(alerts_path, references, margin=Decimal(0)):
    margin = Decimal(str(margin))
    if not margin.is_finite() or margin < 0:
        raise ValueError("evaluation margin must be finite and nonnegative")
    counters = {attack: {"true_alerts": 0, "false_alerts": 0} for attack in ATTACKS}
    first = {}
    with open(alerts_path, encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            timestamp = Decimal(row["timestamp"])
            if not timestamp.is_finite() or row["attack"] not in counters:
                raise ValueError("invalid alert timestamp/attack")
            candidates = [
                r
                for r in references
                if r.attack == row["attack"]
                and r.start - margin <= timestamp <= r.end + margin
                and (r.src is None or r.src == row["src"])
                and (r.dst is None or r.dst == row["dst"])
            ]
            if candidates:
                # A single alert matches one incident, chosen deterministically.
                ref = min(candidates, key=lambda r: (abs(timestamp - r.start), r.incident_id))
                counters[row["attack"]]["true_alerts"] += 1
                first[ref.incident_id] = min(timestamp, first.get(ref.incident_id, timestamp))
            else:
                counters[row["attack"]]["false_alerts"] += 1
    result = {}
    for attack in ATTACKS:
        relevant = [r for r in references if r.attack == attack]
        delays = {
            r.incident_id: str(first[r.incident_id] - r.start)
            for r in relevant
            if r.incident_id in first
        }
        matched = len(delays)
        tp, fp = counters[attack]["true_alerts"], counters[attack]["false_alerts"]
        result[attack] = {
            **counters[attack],
            "true_positive_intervals": matched,
            "false_negative_intervals": len(relevant) - matched,
            "reference_intervals": len(relevant),
            "precision_alert_level": tp / (tp + fp) if tp + fp else None,
            "recall_incident_level": matched / len(relevant) if relevant else None,
            "first_detection_delay_seconds": delays,
        }
    return {
        "margin_seconds": str(margin),
        "attacks": result,
        "method": "alert precision; independently labeled incident recall; capture-time delay",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--alerts", required=True, type=Path)
    parser.add_argument("--reference", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--margin", default="0")
    args = parser.parse_args(argv)
    try:
        result = evaluate(args.alerts, load_references(args.reference), args.margin)
        with args.out.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, allow_nan=False)
            stream.write("\n")
    except (OSError, ValueError, KeyError, InvalidOperation) as exc:
        parser.exit(2, f"evaluation: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
