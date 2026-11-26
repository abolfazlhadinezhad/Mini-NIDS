# Mini-NIDS

Streaming Python intrusion detection for Ethernet PCAP files. All seven protocol
parsers use `struct`; bounded state and contextual rules detect ARP spoofing,
vertical TCP/UDP scans, SYN floods and DNS spoofing.

**Validation scope:** deterministic synthetic captures, independent tshark
comparisons and Windows/Linux CI. Instructor PCAPs were not supplied, so academic
dataset metrics and threshold calibration remain pending. Optional live capture
and Slowloris are not implemented.

## Installation and analysis

Python 3.11+. Offline runtime requires only the standard library.

```powershell
cd E:\PROJECTS\NETWORK
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev,report]"
.\.venv\Scripts\python.exe nids.py --pcap datasets/ARPspoofing-stu.pcap --out outputs/arp-run-1
.\.venv\Scripts\mini-nids.exe --pcap datasets/DoS-SYN-stu.pcap --out outputs/syn-run-1 --config config/default.json
```

On Linux/macOS, create the venv with `python3` and use `.venv/bin/python`.
Runtime-only installation: `python -m pip install .`. Another entry point is
`python -m mininids`.

Use a fresh output directory each run; existing output files are never
overwritten. Exit codes: 0 complete, 2 invalid input/configuration or failed run,
130 interrupted. A failed/interrupted run retains partial output and records its
status in run.json after processing has started.

Classic PCAP 2.4 with Ethernet linktype 1, both byte orders, micro/nanosecond
timestamps and VLAN/QinQ work. PCAPNG and non-Ethernet linktypes are rejected;
convert explicitly with `editcap -F pcap input.pcapng output.pcap`.

## Outputs per capture

| File | Contents |
|---|---|
| alerts.csv | Triggering timestamp, rule_id, attack, src, dst, JSON evidence |
| alert_aggregates.csv | First/last timestamp, matches and suppressed repeats |
| dns.csv | Full questions, typed answers/TTL, query match, response code, RTT |
| flows.jsonl | Bidirectional tuples, directional counts/bytes, flags, TCP state/timing |
| timeseries.csv | Sparse packet/wire-byte/SYN counts per capture-watermark second |
| stats.json | Duration, hierarchy, sizes, flags, talkers, errors and resource losses |
| run.json | Input, version, full configuration, processing status and policies |

The first alert is flushed immediately. Repeats are summarized by rule/key;
new TCP classification evidence may produce another supporting rule alert.
See [RULES.md](docs/RULES.md) for thresholds, evidence and benign analogues.

## Reproduce validation

These utilities only write local files and transmit no packets.

```powershell
.\.venv\Scripts\python.exe -m tools.generate_fixtures --out outputs/fixtures-1
.\.venv\Scripts\python.exe -m tools.evaluate_suite --manifest outputs/fixtures-1/manifest.json --out outputs/evaluation-1
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
```

Every detector runs against every generated capture. Scan threshold sensitivity
uses 10, 20 and 40 ports. Synthetic reference intervals are fixed before analysis;
synthetic accuracy does not establish real-network accuracy.

Independent comparison, using your installed tshark executable:

```powershell
.\.venv\Scripts\python.exe -m tools.compare_tshark --tshark "C:/Program Files/Wireshark/tshark.exe" --pcap outputs/fixtures-1/benign.pcap outputs/fixtures-1/parser-reference.pcap --out outputs/comparison-1.json
```

This compares timestamps, capture/wire lengths and supported parsed fields,
including raw TCP sequence numbers. CI also compares every attack fixture.

## Course evaluation, benchmark and package

Put the exact instructor slices inside ignored datasets/. First inspect them
independently in Wireshark/tshark and write reference intervals as described in
[DATASETS.md](docs/DATASETS.md). Adapt config/course-manifest.example.json.

```powershell
.\.venv\Scripts\python.exe -m tools.evaluate_suite --manifest config/course-manifest.example.json --out outputs/course-evaluation-1
.\.venv\Scripts\python.exe -m mininids.evaluation --alerts outputs/arp-run-1/alerts.csv --reference datasets/arp.reference.json --out outputs/arp-metrics-1.json
.\.venv\Scripts\python.exe -m tools.benchmark --pcap datasets/DoS-SYN-stu.pcap --out outputs/course-benchmark-1
.\.venv\Scripts\python.exe -m tools.benchmark --generate-packets 100000 --out outputs/benchmark-1
.\.venv\Scripts\python.exe -m build
```

Metrics distinguish alert-level precision from incident-level recall; undefined
ratios are null. Delay uses capture time. The benchmark includes output I/O and
allocation tracing, reports Python allocation peak and process peak RSS, and
does not claim live line rate. Benchmark the largest supplied capture for the
academic requirement.

## Engineering documents

- [Requirements/traceability](REQUIREMENTS.md), [plan](PROJECT_PLAN.md), [architecture](ARCHITECTURE.md)
- [Implementation status](IMPLEMENTATION_STATUS.md), [validation evidence](reports/VALIDATION.md)
- [Rules](docs/RULES.md), [datasets](docs/DATASETS.md), [limitations](docs/LIMITATIONS.md)
- [Report source](docs/REPORT.md), reports/Mini-NIDS-Engineering-Report.pdf
- [Git workflow](GIT_WORKFLOW.md)

Core code is in mininids/; each rule has a separate mininids/rules/ module. Tests
are separate from the runtime package. Scapy is used for independent fixtures,
and ReportLab for the engineering report.

Checksums are retained without attack verdicts. IPv4 fragments are counted but
not reassembled. IPv6 dissection, DNS-over-TCP and encrypted DNS are unsupported.
Hard memory bounds trade detection context for safety; output disk usage grows.
