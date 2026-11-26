"""Validated configuration; defaults are illustrative, not dataset-trained."""

import json
import math
from dataclasses import asdict, dataclass, fields
from pathlib import Path


@dataclass(frozen=True)
class Config:
    max_flows: int = 20_000
    max_mappings: int = 4_096
    max_queries: int = 10_000
    max_rule_keys: int = 1_024
    max_window_items: int = 256
    max_packet_bytes: int = 1_048_576
    idle_timeout: float = 60.0
    active_timeout: float = 300.0
    arp_timeout: float = 300.0
    dns_timeout: float = 10.0
    window_seconds: float = 10.0
    scan_ports: int = 20
    syn_rate: float = 100.0
    syn_incomplete_ratio: float = 0.8
    arp_conflicts: int = 3
    arp_stable_observations: int = 2
    alert_cooldown: float = 10.0

    def __post_init__(self):
        for key, value in asdict(self).items():
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{key} must be numeric")
            if not math.isfinite(value) or value <= 0:
                raise ValueError(f"{key} must be positive and finite")
            if fields(type(self))[[f.name for f in fields(type(self))].index(key)].type is int:
                if not isinstance(value, int):
                    raise ValueError(f"{key} must be an integer")
        if self.syn_incomplete_ratio > 1:
            raise ValueError("syn_incomplete_ratio must be at most one")
        if self.scan_ports > self.max_window_items:
            raise ValueError("scan_ports exceeds max_window_items")

    @classmethod
    def from_file(cls, path: Path | str):
        with open(path, encoding="utf-8") as stream:
            values = json.load(stream)
        if not isinstance(values, dict):
            raise ValueError("configuration must be a JSON object")
        unknown = values.keys() - {f.name for f in fields(cls)}
        if unknown:
            raise ValueError(f"unknown configuration fields: {sorted(unknown)}")
        return cls(**values)

    def as_dict(self):
        return asdict(self)
