# Validation and delivery evidence

Date: 2026-11-26. Scope: mandatory offline software. Real course-dataset
evaluation is **pending**, not verified. Machine-readable summaries are in
reports/evidence/. Raw generated captures and full per-capture outputs remain
under ignored outputs/.

## Executed checks

| Check | Observed result |
|---|---|
| pytest on local Python 3.13.13 | 127 passed; 0 failures/errors/skips |
| Ruff lint and formatting | Passed |
| Synthetic suite | All 4 attack scenarios detected; benign fixture 0 alerts |
| Detector/capture matrix | Expected ARP, scan, SYN and three DNS rules; no unexpected attack-family cross-alerts |
| Scan sensitivity | Threshold 10: 0.9 s delay; 20: 1.9 s; 40: no detection of the 25-port fixture |
| tshark 4.6.10 field comparison | 1,270 packets; 27,652 field comparisons; 0 mismatches |
| Capacity stress | Every table within its configured cap after every packet |
| Synthetic benchmark | 100,000 packets; 36.108 s; 2,769.4 packets/s with tracing/output I/O |
| Peak memory in benchmark | Python allocations 29.43 MiB; process peak RSS 100.54 MiB |
| Packaging | Source archive and wheel build; runtime-only isolated wheel analysis succeeds |
| Report | Six-page PDF generated, text bounds checked and rendered pages visually inspected |
| Source PDF preservation | Working-tree Git blob equals the original tracked blob; no modification/recommit |

The benchmark is synthetic, not the largest course capture and not a live line
rate. Its core workload contains unique SYN tuples; final DNS fingerprint
hardening does not alter that workload. Packet parsing comparison covers fields
present in supported decoded headers; it does not validate unsupported dissections.

## Synthetic detection evidence

| Capture | Alerts | First correct delay |
|---|---|---|
| benign | None | Not applicable |
| arp | ARP-1 | 0.200 s |
| scan | SCAN-TCP, SCAN-1 | 1.900 s |
| syn | SYN-1 | 1.998 s |
| dns | DNS-2, DNS-3, DNS-1 | 0.010 s |

Each attack fixture has one predetermined incident; each is detected with no
outside-interval/type false alert in this fixture suite. This small deterministic
result is software regression evidence, not an estimate of real-network
precision or recall. DNS-1 arrives later than the first DNS L2/cross-layer alerts
because the application conflict requires observing the second response.

## Reproduction commands

Run from the repository with the development/report extras installed. Choose
fresh destination directories; outputs are intentionally protected from overwrite.

```powershell
.\.venv\Scripts\python.exe -m pytest -q --junitxml=outputs/pytest-final.xml
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
.\.venv\Scripts\python.exe -m tools.generate_fixtures --out outputs/new-fixtures
.\.venv\Scripts\python.exe -m tools.evaluate_suite --manifest outputs/new-fixtures/manifest.json --out outputs/new-evaluation
.\.venv\Scripts\python.exe -m tools.compare_tshark --tshark .tools/wireshark/App/Wireshark/tshark.exe --pcap outputs/new-fixtures/benign.pcap outputs/new-fixtures/arp.pcap outputs/new-fixtures/scan.pcap outputs/new-fixtures/syn.pcap outputs/new-fixtures/dns.pcap outputs/new-fixtures/parser-reference.pcap --out outputs/new-comparison.json
.\.venv\Scripts\python.exe -m tools.benchmark --generate-packets 100000 --out outputs/new-benchmark
.\.venv\Scripts\python.exe -m tools.report --suite outputs/new-evaluation/suite.json --comparison outputs/new-comparison.json --benchmark outputs/new-benchmark/benchmark.json --junit outputs/pytest-final.xml --timeseries outputs/new-evaluation/syn/timeseries.csv --out outputs/new-report.pdf
.\.venv\Scripts\python.exe -m build
```

The local portable tshark path is ignored and not distributed. On another host,
install Wireshark/tshark separately and pass its executable. CI installs tshark
on Linux and performs the same full comparison. No capture driver, live replay,
attack tools or changes to unrelated projects were needed.

## GitHub CI and correction evidence

Workflow: .github/workflows/ci.yml. Four test/build jobs cover Windows/Linux and
Python 3.11/3.13; a fifth independently compares all six fixtures with Linux
tshark. Run 45794577337 at b69b1f9 passed all five jobs. Subsequent commits rerun
the same workflow; final integration is recorded below.

The workspace-scoped pytest temporary path also exposed a fresh-clone issue:
pytest creates its base directory but not a missing outputs/ parent. The test
configuration now creates that parent, verified with a previously absent nested
base path. This changes test setup, not detector behavior.

The first CI attempt passed all four test/build jobs but failed Linux tshark
file access. Logs were inspected; passing the already-open capture as standard
input resolved the restriction. No repository protections were bypassed. Further
review fixed reused TCP tuples, VLAN priority scoping, fabricated ports on
truncated transport headers, DNS transaction lifetime and bounded DNS content.

## Development checkpoints and history

Preserved baseline: 0fe5f48. All work used feature/offline-nids, with a successful
push after each completed checkpoint. Conventional commits before final delivery:

| Commit | Completed unit |
|---|---|
| e5f4503 | Requirements and workflow |
| 7339a22 | Streaming PCAP reader |
| 869f7c6 | Manual protocol parsers |
| 18bd33f | Bounded network state |
| 83ccea0 | ARP conflict detection |
| cdb6c27 | TCP/UDP scan classification |
| 0a7b55b | Destination SYN flood detection |
| 17ccd1b | Three-layer DNS spoofing evidence |
| b472a7e | Integrated CLI and exports |
| c4618e0 | Evaluation and threshold sensitivity |
| 19615d5 | Independent reference, stress test and CI |
| 67d05d2 | TCP timing, tuple reuse and VLAN scope fixes |
| 0b9ac86 | Reference failure diagnostics |
| b69b1f9 | Portable tshark input and source packaging |
| 20652fd | Truncated-port safety and regression tests |
| 8d1cb31 | Bounded complete-DNS fingerprint comparisons |

## Final integration

Additional checkpoints: e894c39 (packaging/workspace test artifacts), 350e8cd
(delivery documentation/PDF/evidence), 4fab486 (fresh-clone test setup). These
complete 19 tested/reviewed feature-branch commits, all pushed successfully.

Feature CI run 45801637445 at 4fab486 passed all five jobs. Merged into main with
history preserved at 1d80b4c15d253afb79509f01ec1341537c83ffd9; pushed to origin and
verified identical via ls-remote. Main CI run 45802235847 passed all five jobs.
The original baseline remains an ancestor and the feature branch is fully
integrated. Final closure documentation follows this verified merge on main.
Exact current main and remote SHAs can be checked with git rev-parse HEAD and
git ls-remote --heads origin main.

## Pending external evidence

The four instructor captures, independently annotated attack intervals, real
baselines, false-positive analysis, real threshold calibration and largest-file
benchmark have not been supplied/measured. The PDF answers conceptual report
questions and demonstrates synthetic behavior; it deliberately identifies the
data-specific answers/screenshots still needed. Optional live monitoring and
Slowloris are deferred. REQUIREMENTS.md gives the per-requirement status.
