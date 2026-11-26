from collections import Counter, OrderedDict, deque

from ..bounded import BoundedTable


def table(config):
    return BoundedTable(config.max_rule_keys, config.window_seconds, config.window_seconds * 2)


class Counts:
    """Fixed-resolution rolling counters: at most 65 buckets per key."""

    def __init__(self, seconds):
        self.seconds, self.width = seconds, seconds / 64
        self.buckets = deque()
        self.total = Counter()

    def add(self, now, name):
        slot = int(now / self.width)
        while self.buckets and self.buckets[0][0] <= slot - 64:
            _, old = self.buckets.popleft()
            self.total.subtract(old)
        if not self.buckets or self.buckets[-1][0] != slot:
            self.buckets.append((slot, Counter()))
        self.buckets[-1][1][name] += 1
        self.total[name] += 1
        return self.total


class Items:
    """Distinct observed items with exact per-item expiry and explicit capacity."""

    def __init__(self, capacity, seconds):
        self.capacity, self.seconds = capacity, seconds
        self.items = OrderedDict()
        self.evictions = 0

    def prune(self, now):
        while self.items and now - next(iter(self.items.values()))[0] >= self.seconds:
            self.items.popitem(last=False)

    def put(self, key, value, now):
        self.prune(now)
        if key not in self.items and len(self.items) >= self.capacity:
            self.items.popitem(last=False)
            self.evictions += 1
        self.items[key] = (now, value)
        self.items.move_to_end(key)
