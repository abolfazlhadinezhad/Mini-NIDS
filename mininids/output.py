"""Incremental machine-readable outputs; immediate first alerts, bounded aggregation."""

import csv
import json
from collections import Counter
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path

from .bounded import BoundedTable


class Outputs:
    FILENAMES = (
        "alerts.csv",
        "alert_aggregates.csv",
        "dns.csv",
        "flows.jsonl",
        "timeseries.csv",
        "stats.json",
        "run.json",
    )

    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        for name in self.FILENAMES:
            if (self.directory / name).exists():
                raise FileExistsError(
                    f"refusing to overwrite existing output: {self.directory / name}"
                )
        self.stack = ExitStack()
        self.alert_stream, self.alerts = self.csv(
            "alerts.csv", ["timestamp", "rule_id", "attack", "src", "dst", "evidence"]
        )
        _, self.aggregates = self.csv(
            "alert_aggregates.csv",
            [
                "first_timestamp",
                "last_timestamp",
                "rule_id",
                "src",
                "dst",
                "matches",
                "suppressed",
                "reason",
            ],
        )
        _, self.dns = self.csv(
            "dns.csv",
            [
                "timestamp",
                "src",
                "dst",
                "src_port",
                "dst_port",
                "transaction_id",
                "response",
                "questions",
                "answers",
                "rcode",
                "matched_query",
                "rtt_seconds",
            ],
        )
        _, self.rates = self.csv(
            "timeseries.csv", ["epoch_second", "packets", "wire_bytes", "syn_packets"]
        )
        self.flows = self.stack.enter_context(
            (self.directory / "flows.jsonl").open("x", encoding="utf-8")
        )

    def csv(self, name, columns):
        stream = self.stack.enter_context(
            (self.directory / name).open("x", encoding="utf-8", newline="")
        )
        writer = csv.DictWriter(stream, columns)
        writer.writeheader()
        return stream, writer

    def flow(self, flow, reason):
        row = asdict(flow)
        row["tcp_flags"] = dict(flow.tcp_flags)
        row["export_reason"] = reason
        row["handshake_complete"] = flow.established_timestamp_ns is not None
        row["handshake_seconds"] = (
            (flow.established_timestamp_ns - flow.syn_timestamp_ns) / 1e9
            if flow.established_timestamp_ns is not None and flow.syn_timestamp_ns is not None
            else None
        )
        row["duration_seconds"] = max(0, flow.last_ns - flow.first_ns) / 1e9
        self.flows.write(json.dumps(row, sort_keys=True) + "\n")

    def dns_packet(self, packet, tx):
        dns, ip, udp = packet.dns, packet.ip, packet.udp
        self.dns.writerow(
            {
                "timestamp": packet.record.timestamp_text,
                "src": ip.src,
                "dst": ip.dst,
                "src_port": udp.src_port,
                "dst_port": udp.dst_port,
                "transaction_id": dns.transaction_id,
                "response": int(dns.response),
                "questions": json.dumps([asdict(q) for q in dns.questions]),
                "answers": json.dumps([asdict(r) for r in dns.answers]),
                "rcode": dns.rcode,
                "matched_query": int(tx is not None),
                "rtt_seconds": (
                    (packet.record.timestamp_ns - tx.timestamp_ns) / 1e9
                    if tx is not None and dns.response
                    else ""
                ),
            }
        )

    def json(self, name, value):
        with (self.directory / name).open("x", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write("\n")

    def close(self):
        self.stack.close()


class AlertSink:
    def __init__(self, config, outputs):
        self.config, self.outputs = config, outputs
        self.pending = BoundedTable(
            config.max_rule_keys, config.alert_cooldown, config.alert_cooldown, self.export
        )
        self.emitted, self.matches = Counter(), Counter()

    def export(self, entry, reason):
        self.outputs.aggregates.writerow(
            {**entry, "suppressed": entry["matches"] - 1, "reason": reason}
        )

    def emit(self, packet, rule_id, attack, src, dst, evidence, key):
        now = self.now
        # Include the VLAN/flow identity even if src/dst are identical across domains.
        identity = (rule_id, key)
        entry = self.pending.get(identity, now, touch=False)
        self.matches[rule_id] += 1
        if entry is not None:
            entry["matches"] += 1
            entry["last_timestamp"] = packet.record.timestamp_text
            return
        self.outputs.alerts.writerow(
            {
                "timestamp": packet.record.timestamp_text,
                "rule_id": rule_id,
                "attack": attack,
                "src": src,
                "dst": dst,
                "evidence": json.dumps(evidence, sort_keys=True, allow_nan=False),
            }
        )
        self.outputs.alert_stream.flush()  # Never delay the first qualifying alert.
        self.emitted[rule_id] += 1
        self.pending.put(
            identity,
            {
                "first_timestamp": packet.record.timestamp_text,
                "last_timestamp": packet.record.timestamp_text,
                "rule_id": rule_id,
                "src": src,
                "dst": dst,
                "matches": 1,
            },
            now,
        )
