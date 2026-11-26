"""Explicitly bounded LRU tables with idle and active expiration."""

from collections import Counter, OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Entry:
    born: float
    last: float
    value: Any


class BoundedTable:
    def __init__(
        self, capacity: int, idle: float, active: float, on_remove: Callable | None = None
    ):
        self.capacity, self.idle, self.active = capacity, idle, active
        self.entries = OrderedDict()
        self.removals = Counter()
        self.on_remove = on_remove
        self.peak = 0

    def __len__(self):
        return len(self.entries)

    def remove(self, key, reason="expired"):
        entry = self.entries.pop(key, None)
        if entry is not None:
            self.removals[reason] += 1
            if self.on_remove:
                self.on_remove(entry.value, reason)

    def get(self, key, now: float, *, touch=True):
        entry = self.entries.get(key)
        if entry is None:
            return None
        if now - entry.last >= self.idle or now - entry.born >= self.active:
            self.remove(key)
            return None
        if touch:
            entry.last = now
            self.entries.move_to_end(key)
        return entry.value

    def put(self, key, value, now: float):
        if key not in self.entries and len(self.entries) >= self.capacity:
            self.remove(next(iter(self.entries)), "capacity")
        old = self.entries.get(key)
        self.entries[key] = Entry(old.born if old else now, now, value)
        self.entries.move_to_end(key)
        self.peak = max(self.peak, len(self.entries))
        return value

    def expire(self, now: float):
        for key, entry in list(self.entries.items()):
            if now - entry.last >= self.idle or now - entry.born >= self.active:
                self.remove(key)

    def close(self):
        for key in list(self.entries):
            self.remove(key, "end_of_capture")


def scope(packet):
    # PCP/DEI can vary within one broadcast domain; identity uses VLAN IDs only.
    return tuple(tag & 0xFFF for tag in packet.ethernet.vlan_tags) if packet.ethernet else ()
