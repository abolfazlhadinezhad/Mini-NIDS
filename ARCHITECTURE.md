# Architecture

`capture records -> manual parsers -> statistics -> bounded state -> rules -> outputs`

Python 3.11+; no runtime dependency for classic Ethernet PCAP analysis. The input
adapter decodes capture envelopes, not protocols. Immutable protocol dataclasses
retain fields. Each packet is released after processing. No future packet alters
an earlier alert; later evidence can refine a subsequent scan classification.

Independent modules:

- `capture`: streaming classic PCAP, endian and micro/nanosecond timestamps.
- `protocols`, `dns`: defensive struct parsing; typed parse diagnostics.
- `bounded`: LRU capacity and capture-time expiry primitives.
- `state`: bidirectional flows/TCP, ARP mappings/requests and DNS transactions.
- `rules/`: separate contextual ARP, TCP/UDP scan, SYN-flood and DNS rules.
- `output`, `stats`: incremental CSV/JSONL files and bounded summaries.
- `engine`, `cli`: orchestration, config, explicit failures and graceful close.
- `evaluation`: independent analyst reference intervals and metrics.

All tables have entry caps and expiry. A packet-time watermark handles backward
timestamps without rewriting original timestamps. Sliding windows count distinct
ports or grouped attempts, not a packet object per packet. Flow evictions stream
to disk; aggregate statistics have bounded key cardinality. State eviction counts
make loss of visibility observable. An attacker cannot force unbounded state by
varying tuples, MACs, DNS names or timestamps.

Checksums are exposed as raw fields; they are not attack evidence because capture
offloading can invalidate their apparent value. Fragmented datagrams cannot feed
complete transport or application rules. Unsupported frames are counted, not
incorrectly decoded as Ethernet/IPv4. Resource caps trade completeness for safety.
