# Requirements and traceability

Authority: `Mini-NIDS.pdf` (22 pages), supplemented by the user's engineering
directive. Page numbers below are printed PDF pages. Implementation filenames
are relative to mininids/ unless a tools/, docs/ or configuration path is given.
Per-row status/evidence below is supported by reports/VALIDATION.md.

| ID | Source | Requirement | Implementation target | Corresponding tests | Validation status | Completion evidence |
|---|---|---|---|---|---|---|
| P01 | pp.3-5,15 | Single-pass raw PCAP, original timestamp, captured/original lengths | capture.py | test_capture.py | Passed unit + independent | test_capture.py; tshark comparison |
| P02 | pp.3,15 | struct Ethernet/VLAN, ARP, IPv4, ICMP, TCP, UDP | protocols.py | test_protocols.py | Passed unit + independent | test_protocols.py; tshark comparison |
| P03 | pp.11-13,15 | DNS compression, questions, types, answers, TTL, rcode | dns.py | test_dns.py | Passed unit + independent | test_dns.py; test_reference_adapter.py |
| P04 | pp.5,15 | Truncation vs malformed; fragments; unsupported L2; checksum caveat | protocols.py | test_protocols.py | Passed unit | truncation/fragment/options/ICMP tests |
| S01 | pp.15-16 | Bidirectional 5-tuple, directional counts/bytes, flags, first/last | state.py | test_state.py | Passed unit/integration | test_state.py; flow exports |
| S02 | pp.9,15-16 | TCP SYN/SYNACK/ACK/FIN/RST/incomplete, retransmissions | state.py | test_state.py | Passed unit | handshake, reset, timing, tuple reuse |
| S03 | pp.7,16 | ARP mapping history and request/reply matching | state.py, rules/arp.py | test_rule_arp.py | Passed unit + synthetic | test_state.py; test_rule_arp.py |
| S04 | pp.12-13,16 | DNS query correlation across IP/ports/ID/question | state.py, rules/dns.py | test_rule_dns.py | Passed unit + synthetic | test_state.py; test_rule_dns.py |
| S05 | pp.3-5,10,16 | Idle/active timeout, bounded state, capture-clock windows | bounded.py, state.py | test_state.py, test_resources.py | Passed stress tests | test_resources.py; 100k benchmark |
| D01 | pp.6-7,20 | Contextual ARP mapping conflict, unsolicited repeated replies | rules/arp.py | test_rule_arp.py | Synthetic passed; real pending | test_rule_arp.py; test_synthetic_suite.py |
| D02 | pp.7-9,21 | Vertical scan; classify SYN vs connect; UDP/ICMP evidence | rules/scan.py | test_rule_scan.py | Synthetic passed; real pending | test_rule_scan.py; test_synthetic_suite.py |
| D03 | pp.9-11,21 | Destination SYN rate and incomplete ratio; victim response | rules/syn.py | test_rule_syn.py | Synthetic passed; real pending | test_rule_syn.py; test_synthetic_suite.py |
| D04 | pp.11-13,21 | At least three DNS-spoof rules at distinct layers; learned context | rules/dns.py | test_rule_dns.py | Synthetic passed; real pending | test_rule_dns.py; test_synthetic_suite.py |
| D05 | pp.4,17 | Rule IDs, protocol justification, no hardcoded identities | config.py, docs/RULES.md | test_rule_dns.py | Implemented and documented | docs/RULES.md; no static detector identities |
| O01 | pp.15-17,22 | alerts.csv: timestamp/rule_id/attack/src/dst/evidence | output.py | test_pipeline.py | Passed integration | test_pipeline.py; per-capture alerts.csv |
| O02 | pp.17-18 | Immediate first alert; suppress/aggregate floods by key/window | output.py | test_pipeline.py | Passed integration | immediate first alert and suppression test |
| O03 | pp.6,10,15,22 | Duration, protocols, sizes, flags, top talkers, per-second rate | stats.py | test_pipeline.py | Passed integration | test_pipeline.py; stats/time-series exports |
| O04 | pp.15-16,22 | DNS log and connection/flow exports per capture | output.py | test_pipeline.py | Passed integration | test_pipeline.py; synthetic DNS/flow exports |
| E01 | pp.4-6,17-18 | Four supplied captures: baseline, onset/end, participants, reference | evaluation.py, docs/DATASETS.md | external captures required | Blocked: missing course files | docs/DATASETS.md lists exact missing slices |
| E02 | pp.4-5,22 | Wireshark/tshark independent parser comparison | tools/compare_tshark.py | independent tool run | Passed on reference captures | 1270 packets; 27652 fields; zero mismatches |
| E03 | pp.17-18 | Per-attack TP/FP/FN, precision/recall, capture-time delay | evaluation.py | test_evaluation.py | Software passed; real pending | test_evaluation.py; synthetic metrics |
| E04 | pp.17-18 | Cross-detector/capture matrix and threshold sensitivity | tools/evaluate_suite.py | synthetic suite; external pending | Synthetic passed; real pending | suite.json; thresholds 10/20/40 |
| E05 | p.18 | Throughput and peak memory on largest supplied capture | tools/benchmark.py | synthetic benchmark; external pending | Synthetic measured; real pending | reports/evidence/benchmark.json |
| R01 | pp.20-22 | Answer report questions, rule catalog, README, final PDF | docs/REPORT.md, report generator | rendered report QA | Report delivered; real evidence pending | docs/REPORT.md; engineering report PDF |
| X01 | pp.18-19 | Optional live shared pipeline, bounded capture, drop/delay counters | deferred (no live.py) | mock capture; real NIC optional | Optional deferred | No live implementation or validation claim |
| X02 | pp.14-16,21 | Optional Slowloris bounded TCP reassembly/HTTP header framing | optional deferred | optional | Optional deferred | No Slowloris implementation claim |

## Conservative decisions and ambiguities

- No numeric thresholds are specified: defaults are illustrative, configurable,
  never presented as learned from the unavailable course captures. Baselines are
  measured in reports and can guide analyst-selected configuration.
- No trusted gateway/resolver identity is assumed. Repeated ARP mapping history,
  exact DNS query correlation and observed resolver L2 history provide context.
  First-seen values are observations, not proof of authenticity.
- Capture order is authoritative. Expiry uses a nondecreasing watermark while
  output preserves each original timestamp; backward timestamps are counted.
- IPv4 fragments are recognized and counted, with no transport interpretation
  until reassembly (not required). Reassembly is explicitly unsupported; this
  creates an evasion/visibility limitation, not evidence of attack.
- TCP scan type is known only after open-port follow-up. Closed-only or filtered
  probes are classified as indeterminate TCP probes, not guessed to be SYN scan.
- DNS over TCP, encrypted DNS, IPv6 dissection and optional Slowloris are outside
  the mandatory implementation. They are counted/documented where observable.
- A student's PCAP slice cannot be recreated by downloading the original public
  dataset: its exact packets, offset and labels are unknown.
- The original PDF is already in baseline commit 0fe5f48. Preserve that history;
  do not recommit, alter, or rewrite it. Generated report PDF is a separate asset.
