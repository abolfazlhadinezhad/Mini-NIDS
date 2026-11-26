# Mini-NIDS engineering and evaluation report

Date: 2026-11-26. Version: 0.1.0. Scope: mandatory offline implementation,
synthetic validation, independent dissection and outstanding academic evidence.
All 22 specification pages were read and visually reviewed, including tables,
grading, report questions and submission requirements.

## 1. Delivered system and evidence boundary

The system implements sequential PCAP input, seven manual protocol parsers,
bounded bidirectional flow/TCP, ARP and DNS state, four attack families,
streaming CSV/JSONL output, incident evaluation and independent comparison.
Protocol decoding uses struct. Scapy generates independent reference captures;
it is not a runtime parser dependency.

The four exact course captures were not supplied. This report therefore cannot
claim measured course accuracy, independently identified real attack intervals,
discovered real attackers, calibrated course baselines or performance on the
largest course capture. Those academic evidence requirements remain unfinished.
Synthetic fixtures do not replace them. Live monitoring and Slowloris are
optional and unimplemented.

## 2. Parser and capture design

The input adapter reads one bounded classic PCAP record at a time, retaining
captured length, original length and integer nanosecond timestamp. Both byte
orders and micro/nanosecond precision work. PCAPNG and non-Ethernet linktypes
are rejected with conversion guidance.

Ethernet/VLAN, Ethernet/IPv4 ARP, IPv4, ICMP, TCP and UDP headers are manually
unpacked. DNS questions and all record sections retain class/type/TTL/rcode;
compression traversal is bounded and cycle-safe. A/AAAA and common name/text
records are decoded; unknown RDATA remains hex. DNS TCP/encryption and IPv6
dissection are explicitly unsupported.

Captured bytes may be shorter than IPv4 Total Length or UDP Length. A truncated
payload does not invalidate a complete earlier header. Original wire length is
a separate bound. IPv4 MF/offset are retained, but fragments never become
fabricated TCP/UDP/DNS packets. ICMP errors are parsed at the outer layer before
the quoted IP and transport fields; embedded DNS is not a new DNS transaction.

Checksums are retained, not used as attack evidence. Offloading can calculate
checksums after the capture point; truncation may prevent verification. Neither
condition proves malicious traffic. No attacker, gateway, subnet or resolver
identity is hardcoded.

## 3. Network state and memory

Flow keys are bidirectional IP/port/protocol tuples plus VLAN IDs. PCP/DEI
changes do not create new broadcast domains. Each direction has packet,
captured-byte and wire-byte counts. TCP follows SYN_SENT, SYN_ACK_RECEIVED,
ESTABLISHED, FINISHED, RESET and INCOMPLETE. The final ACK must match both
sequence spaces. SYN, SYN-ACK, establishment and close timestamps are retained.
Adjacent duplicate SYN/data signatures provide limited retransmission counts.

A new SYN sequence on a reused tuple exports the old flow and starts another.
FIN from both directions marks FINISHED; RST marks RESET. Midstream traffic
without a witnessed handshake remains INCOMPLETE. This passive model does not
claim full endpoint semantics, arbitrary reordering or TCP stream reconstruction.

ARP state retains incumbent MAC, first observation and observation count, plus
earlier request/reply matching. DNS matches both IPs, both UDP ports, transaction
ID, all questions and VLAN. A new query after a completed transaction starts a
fresh lifetime; pending retransmissions cannot prolong context indefinitely.

DNS correlation stores fingerprints of complete question vectors and answer
sets/rcode, with only a bounded previous-answer sample in memory. Full DNS
records are streamed to disk. Comparing the fingerprint of the complete answer
set catches a conflict even beyond the retained sample.

LRU entry caps and idle/active expiry bound every state table. Expiry sweeps run
at most once per capture-watermark second. Scan keys hold at most 256 ports;
SYN/ARP counters use 64 aggregate time buckets. Tables export flows on expiry,
capacity eviction and EOF. Statistics expose context loss.

Backward timestamps remain intact in output; expiration and sparse traffic
buckets use a nondecreasing capture watermark. Empty gaps do not require one
row per empty second. The first qualifying alert is flushed immediately;
subsequent matches are summarized in a separate CSV. Memory is bounded by
configuration, but output disk usage grows with exported records.

## 4. Rules and protocol justification

ARP-1 requires repeated unsolicited, nongratuitous conflicting replies against
an incumbent observed at least twice. ARP lacks origin authentication, but a
single legitimate mapping change is insufficient. Stable history, repetition
and request context reduce false alerts; poisoned baselines remain a limitation.

TCP scan detection aggregates distinct ports per visible source/destination.
Closed-port RST behavior cannot distinguish SYN and connect scanning. On open
ports, SYN-ACK then initiator RST supports SYN-style scanning; a sequence-valid
final ACK supports connect-style scanning. Until follow-up is sufficient the
classification is indeterminate TCP probes. UDP fanout is weaker; correlated
ICMP type 3/code 3 quotations add closure evidence. Silence is open OR filtered.

SYN-1 aggregates by destination because sources can be distributed/spoofed. It
combines full-window SYN rate with an estimated high incomplete-handshake ratio.
Evidence includes SYN/SYN-ACK/completion/reset counts, flags, size and payload.
The ratio is an aggregate estimate, not a direct observation of kernel backlog;
boundary-crossing completions, packet loss and asymmetric capture can bias it.

DNS-1 compares conflicting semantic answer sets in one fully correlated
transaction; answer order and TTL changes alone do not create a conflict.
DNS-2 compares a correlated response's Ethernet source with a stable ARP mapping
for that exact resolver IP. DNS-3 compares Ethernet/IP consistency with repeated
prior responses from that resolver. These three layers provide complementary
observations, not cryptographic authentication. All rules, thresholds, benign
analogues and mitigations appear in docs/RULES.md.

## 5. Validation and measurement methodology

The tests cover protocol fields, both PCAP byte orders/precisions, malformed and
capture-truncated bytes, VLANs, fragments, ICMP quotation, DNS compression and
pointer failures, TCP transitions/tuple reuse, state expiry, all detectors and
benign analogues. Deterministic random bytes test safe failure. Capacity stress
tests assert table bounds after each packet.

Independent Scapy fixtures include a shared benign prefix and four attacks.
The manifest fixes reference intervals before running detection. Every detector
runs on every fixture; scan sensitivity uses 10, 20 and 40 ports. These results
establish expected software behavior on known inputs, not statistical
generalization to the unavailable course files.

Streaming tshark comparison checks original timestamps, capture/wire lengths,
Ethernet/VLAN, ARP, IPv4, TCP raw sequence/acknowledgment/flags/window/length,
UDP, ICMP and DNS fields supported by the manual parser. Unparsed unsupported
fields are not claimed validated. Results are included in the evidence appendix.

Precision is alert-level: correct matching alerts divided by all alerts. Recall
is incident-level: independently labeled intervals with at least one correct
alert divided by all intervals. Wrong type, participants or interval yields a
false alert. One incident counts once for recall even if several rules support
it. Undefined denominators are null. Delay is earliest correct capture timestamp
minus the independently labeled start, with any declared margin kept explicit.

The benchmark includes output I/O and tracemalloc overhead, reporting Python
allocation peak and process peak RSS. Synthetic stress demonstrates engineering
behavior; the largest real course capture still needs its own measured run.

## 6. Shared report questions from specification section 10

### 6.1 A complete benign exchange

The synthetic timeline observes ARP replies at layer 2, UDP/53 query and matching
DNS answer at layers 3/4/7, then TCP SYN/SYN-ACK/ACK followed by FIN in both
directions. Logs retain all relevant fields. Equivalent real-data frame numbers
and screenshots remain pending because the course captures are absent.

### 6.2 Next-hop MAC, IP endpoints and NAT

Ethernet addresses identify local next hops; IP identifies routed endpoints at
the capture point. Many remote IPs therefore share a router MAC. NAT may rewrite
source IP/port, so the visible source can be a gateway rather than a physical
attacker. Neither shared MAC nor post-NAT IP proves attribution.

### 6.3 Aggregation keys and legitimate load

A vertical scan asks which ports one visible source probes at one destination.
A SYN flood asks which victim receives excessive incomplete requests regardless
of source diversity. Source-keyed flood rules split distributed load into
apparently harmless fragments. Destination aggregation preserves combined load.
IoT startup, browsers, backups and management systems can also be noisy; measure
baseline fanout, rate, completions, payload and ARP/DNS behavior before tuning.

### 6.4 Encrypted DNS and cross-layer propagation

DoT/DoH hides questions/answers from this passive parser, disabling DNS content
rules. Visible ARP/Ethernet and TCP rate/flow rules still apply. ARP poisoning
can put an observer in the victim's path; it sees a DNS query, copies the tuple,
ID and question, and races a false answer. Classic DNS transaction checks do not
authenticate the Ethernet sender. A later genuine answer can expose a conflict,
while earlier L2 inconsistency can provide evidence without look-ahead.

## 7. ARP questions

The synthetic attacker MAC is 02:00:00:00:00:99, claiming 10.0.0.1 previously
observed at 02:00:00:00:00:01. These are fixture values, not detector constants.
Alert evidence records both MACs, the claimed IP and repeated conflict count.

DHCP reassignment, NIC replacement and router failover can change mappings.
Gratuitous messages alone and replies to observed requests are excluded, and
stable history/repetition are required. A reply is unsolicited when no matching
earlier request remains in state; no future packet is consulted. Missing capture
or expired state does not prove a request never existed.

Attackers repeat poisoning because caches age and legitimate traffic can repair
them. One direction may be visible or poisoned because capture placement and
attack intent differ. Long gaps expire context and can lower recall; keeping old
counts indefinitely would create false positives. Both failure modes are
documented rather than hidden by packet-time rewriting.

## 8. Port scan and SYN flood questions

A single probe is often benign. Port fanout, reply patterns, connection state
and time windows reveal behavior. SYN/connect probes have identical closed-port
responses; only open-port follow-up distinguishes them. UDP silence is ambiguous
and ICMP rate limiting removes closure evidence. Quoted tuple matching prevents
unrelated errors from being assigned to a probe.

NAT client aggregates, browsers and authorized managers can legitimately use
many services. Per-destination scoping, distinct-port counting, handshake
classification and baseline calibration reduce noise but cannot infer permission.

The synthetic SYN fixture sends small SYN-only segments from many sources to
one victim without completing handshakes; its benign prefix completes TCP.
Real victim SYN-ACK/RST response, size distribution and onset/end still require
course-capture measurement. SYN cookies avoid allocating ordinary backlog state
for every initial SYN. Backlog tuning and rate controls can help, but per-source
limits weaken against distributed/spoofed sources and do not remove overload.

## 9. DNS questions

An on-path observer learns rather than guesses the UDP tuple, ID and question.
UDP has no handshake and classic DNS does not cryptographically authenticate
the response origin. Copying those fields can satisfy endpoint matching and let
the first false answer win. The later genuine response can be discarded by an
endpoint even though it gives an observer conflict evidence.

The synthetic race has MAC 02:00:00:00:00:99 answer first and the prior MAC answer
later with different content. DNS-2/DNS-3 can alert immediately using prior
observations. DNS-1 must wait for the conflicting response. Their timestamps
preserve this causal distinction; offline look-ahead cannot move DNS-1 earlier.

Identical duplicates, ID reuse, legitimate resolver diversity, mDNS, quoted DNS
and truncated messages are not sufficient evidence alone. Full keys, canonical
answers and stable per-resolver/ARP context reduce false alerts. Route changes
and legitimate conflicts can still alert and require analyst investigation.

Link defenses include DHCP snooping/dynamic ARP inspection with a valid binding
source; network defenses include segmentation and controlled resolver policy.
DNSSEC can authenticate signed DNS data with correct chain-of-trust validation.
Encrypted DNS protects a transport path but does not by itself authenticate all
upstream authoritative answers. Deployment prerequisites matter for each defense.

## 10. Optional questions and remaining academic submission work

If live processing falls below arrival rate, NIC/kernel/capture/application
queues fill, latency rises and packets drop. This version makes no live-rate or
drop claims. The PDF's replay and attack commands were read as examples and
were not executed against any network.

Slowloris keeps many established connections alive with incomplete HTTP headers
and low byte rates, so SYN-rate detection misses its application behavior.
It would require bounded sequence-aware TCP reconstruction, retransmission and
out-of-order handling, and CRLF-CRLF framing. These optional features are not
claimed as delivered.

Complete academic evaluation by obtaining the exact four student captures,
independently annotating their intervals/participants, measuring baselines,
freezing/tuning thresholds, inspecting every false alert, filling the cross-file
matrix, adding real screenshots and benchmarking the largest file. Tooling and
formats are delivered; the missing evidence is explicitly pending.

## 11. References

Academic authority: local Mini-NIDS.pdf, all 22 pages. Protocol grounding:
RFC 826 (ARP), RFC 791 (IPv4), RFC 792 (ICMP), RFC 768 (UDP), RFC 9293 (TCP),
RFC 1035 (DNS), and the PCAP capture-format description. Dataset provenance:
Canadian Institute for Cybersecurity, University of New Brunswick, pages linked
in docs/DATASETS.md. Independent tools: Scapy and Wireshark/tshark.
