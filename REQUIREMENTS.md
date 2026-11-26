# Requirements and traceability

Authority: `Mini-NIDS.pdf` (22 pages), supplemented by the user's engineering
directive. Page numbers below are printed PDF pages. Status begins as planned;
final evidence is recorded in IMPLEMENTATION_STATUS.md and reports/VALIDATION.md.

| ID | Source | Requirement | Implementation target | Test/evidence target |
|---|---|---|---|---|
| P01 | pp.3-5,15 | Single-pass raw PCAP, original timestamp, captured/original lengths | capture.py | test_capture.py |
| P02 | pp.3,15 | struct Ethernet/VLAN, ARP, IPv4, ICMP, TCP, UDP | protocols.py | test_protocols.py |
| P03 | pp.11-13,15 | DNS compression, questions, types, answers, TTL, rcode | dns.py | test_dns.py |
| P04 | pp.5,15 | Truncation vs malformed; fragments; unsupported L2; checksum caveat | protocols.py | test_protocols.py |
| S01 | pp.15-16 | Bidirectional 5-tuple, directional counts/bytes, flags, first/last | state.py | test_state.py |
| S02 | pp.9,15-16 | TCP SYN/SYNACK/ACK/FIN/RST/incomplete, retransmissions | state.py | test_state.py |
| S03 | pp.7,16 | ARP mapping history and request/reply matching | state.py, rules/arp.py | test_rules.py |
| S04 | pp.12-13,16 | DNS query correlation across IP/ports/ID/question | state.py, rules/dns.py | test_rules.py |
| S05 | pp.3-5,10,16 | Idle/active timeout, bounded state, capture-clock windows | bounded.py, state.py | test_state.py, test_resources.py |
| D01 | pp.6-7,20 | Contextual ARP mapping conflict, unsolicited repeated replies | rules/arp.py | test_rules.py |
| D02 | pp.7-9,21 | Vertical scan; classify SYN vs connect; UDP/ICMP evidence | rules/scan.py | test_rules.py |
| D03 | pp.9-11,21 | Destination SYN rate and incomplete ratio; victim response | rules/syn.py | test_rules.py |
| D04 | pp.11-13,21 | At least three DNS-spoof rules at distinct layers; learned context | rules/dns.py | test_rules.py |
| D05 | pp.4,17 | Rule IDs, protocol justification, no hardcoded identities | config.py, docs/RULES.md | test_rules.py |
| O01 | pp.15-17,22 | alerts.csv: timestamp/rule_id/attack/src/dst/evidence | output.py | test_pipeline.py |
| O02 | pp.17-18 | Immediate first alert; suppress/aggregate floods by key/window | output.py | test_pipeline.py |
| O03 | pp.6,10,15,22 | Duration, protocols, sizes, flags, top talkers, per-second rate | stats.py | test_pipeline.py |
| O04 | pp.15-16,22 | DNS log and connection/flow exports per capture | output.py | test_pipeline.py |
| E01 | pp.4-6,17-18 | Four supplied captures: baseline, onset/end, participants, reference | evaluation.py, docs/DATASETS.md | external captures required |
| E02 | pp.4-5,22 | Wireshark/tshark independent parser comparison | tools/compare_tshark.py | independent tool run |
| E03 | pp.17-18 | Per-attack TP/FP/FN, precision/recall, capture-time delay | evaluation.py | test_evaluation.py |
| E04 | pp.17-18 | Cross-detector/capture matrix and threshold sensitivity | tools/evaluate_suite.py | synthetic suite; external pending |
| E05 | p.18 | Throughput and peak memory on largest supplied capture | tools/benchmark.py | synthetic benchmark; external pending |
| R01 | pp.20-22 | Answer report questions, rule catalog, README, final PDF | docs/REPORT.md, report generator | rendered report QA |
| X01 | pp.18-19 | Optional live shared pipeline, bounded capture, drop/delay counters | live.py | mock capture; real NIC optional |
| X02 | pp.14-16,21 | Optional Slowloris bounded TCP reassembly/HTTP header framing | optional deferred | optional |

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
