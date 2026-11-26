# Detection rule catalog

All identities come from observed traffic. Defaults are engineering examples,
not calibrated course-dataset thresholds. Alerts indicate suspicious behavior,
not authenticated attribution. All keys include VLAN IDs (PCP/DEI excluded).

| Rule | Protocol justification and evidence | Similar benign behavior and mitigation |
|---|---|---|
| ARP-1 | At least 3 unsolicited, nongratuitous replies in 10 s conflict with an incumbent observed at least twice. ARP lacks sender authentication. Evidence includes claimed IP, old/new MAC, observations, count and threshold. | Failover, address reassignment and ARP cache repair can change mappings. Solicited and gratuitous announcements alone are excluded; require prior stability and repetition. Initial observation may itself be poisoned. |
| SCAN-TCP | At least 20 distinct destination ports per source/destination in 10 s; SYN retransmissions do not increase distinct count. Evidence includes ports, statuses and threshold. | NAT gateways, service discovery, browsers and management systems can fan out. Scope is one destination, count distinct ports, inspect follow-up and tune on benign baseline. This remains heuristic. |
| SCAN-1 | At least 20 probed open ports return SYN-ACK and receive initiator RST before a valid final ACK. | Health checks may intentionally perform half-open tests. Authorized scanning is indistinguishable by packet mechanics. |
| SCAN-2 | At least 20 probed ports complete a sequence-checked handshake. | Legitimate clients may use many services. The rule identifies connect-style probing, not intent; compare payload, duration and baseline before attribution. |
| SCAN-UDP | At least 20 distinct destination UDP ports in 10 s. | UDP is connectionless and silence means open OR filtered. DNS/service discovery and dynamic media require baseline inspection. No claim that silence proves closure. |
| SCAN-3 | UDP scan with at least 20 ICMP type 3/code 3 responses matched to the quoted original source/destination IP and UDP ports. | Quoted packets are not fresh DNS/TCP traffic. ICMP rate limiting and asymmetric visibility lower confidence and recall. |
| SYN-1 | Destination-IP aggregation over a 10 s rolling counter; at least 100 unique observed SYN attempts/s and at least 0.8 estimated incomplete ratio. SYN-ACK/completion/reset counters and current flags, payload/wire size are exported. | Startup bursts and flash crowds can be large. Require both rate and completion asymmetry; deduplicate retained SYN retransmissions. Tune on the measured benign interval. Asymmetry and eviction can bias estimates. |
| DNS-1 | Two conflicting semantic answer sets in the same exact query transaction. Match VLAN/client IP+port/resolver IP+port/ID/all questions; ignore answer order and TTL changes. | ID reuse, load balancing and retransmissions do not alone prove spoofing. New queries reset completed transaction context; identical answers are suppressed. Genuine variable duplicate answers may still alert. |
| DNS-2 | Correlated DNS response source MAC conflicts with a stable ARP mapping for that exact resolver IP. | Remote resolvers normally use the local next hop MAC. Never compare that MAC with an imaginary remote ARP entry. Genuine local failover can still alert. |
| DNS-3 | Correlated resolver-IP response arrives from a different Ethernet source after two consistent prior observed responses. | Alternate paths, routers, NIC failover and MAC randomization can change L2 identity. History is per resolver, not an assumed default gateway; exact query match and repeated history reduce noise. |

## Window, expiry and aggregation semantics

Scan items expire exactly when their last probe age reaches window_seconds.
Counts for ARP and SYN use 64 fixed buckets across window_seconds; a boundary
bucket can be dropped up to window_seconds/64 early. Counts therefore slightly
underestimate boundary activity. SYN rate divides by the full window even during
warm-up, preventing a one-packet startup spike.

The SYN completion ratio is an aggregate estimate, not a cohort-perfect backlog
measurement: completions near window boundaries may belong to older SYNs.
Incomplete retained flows and full flow timing are available for analyst review.
Evicting a flow can lose retransmission deduplication; all capacity losses are
reported. One cannot infer the victim's actual kernel backlog from this capture.

The first qualifying rule/key alert is written and flushed immediately.
Subsequent matches within alert_cooldown are summarized in alert_aggregates.csv;
alerts.csv remains immutable. Summary rows preserve first/last capture timestamps,
match counts and suppressed counts. A new period can emit a new alert. Changing
TCP classification has its own rule ID and may emit additional supporting alerts.

## Default resource limits

- 20,000 bidirectional flows; 60 s idle / 300 s active timeout.
- 4,096 ARP mappings and requests; mappings 300 s idle / 600 s active.
- 10,000 DNS transactions; 10 s fixed lifetime. Repeated pending queries do not
  extend it. A new query after a completed transaction starts a fresh lifetime.
- 1,024 keys per detector table / aggregation table.
- 256 distinct ports per scan key, 64 count buckets per rate/conflict key.
- 4,096 source and destination keys in summary statistics; overflow observations
  are counted separately, so top lists are explicitly bounded approximations.
- 1 MiB maximum captured record; 1,024 DNS questions+records; four VLAN tags.

No threshold uses checksums, a memorized attacker address, a public resolver list
or a static gateway MAC. Idle and active expiration use a monotonic capture
watermark; packet output retains the original timestamp. Timestamps going backward
are counted. Sparse time-series buckets use that watermark and omit empty gaps.

DNS state retains SHA-256 fingerprints of the complete ordered question vector
and canonical answer set/rcode. It does not retain arbitrary full message content
per outstanding query. A previous-answer sample is limited to eight records with
256 value characters each; complete records are streamed to dns.csv. Fingerprint
collisions are a theoretical residual risk, not a truncation-based equality test.
