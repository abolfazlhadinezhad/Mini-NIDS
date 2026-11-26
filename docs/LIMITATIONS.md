# Operational and validation limits

- Classic PCAP 2.4 with Ethernet linktype 1 only. Both endian orders and
  micro/nanosecond timestamps work. Convert PCAPNG explicitly with editcap; Linux
  cooked/raw-IP/radiotap/loopback linktypes are rejected with an actionable error.
- IPv4 fragments are counted and never treated as complete transport/application
  packets. No IP reassembly: fragmented attacks can evade these transport rules.
- IPv6, 802.3 LLC/CDP, LLDP, nonstandard ARP and unknown EtherTypes are outside
  dissection scope. Unknown L2/IP traffic is counted; unsupported ARP layouts
  produce a diagnostic. VLAN/QinQ are handled, at most four nested tags.
- DNS is decoded on complete UDP/53 payloads. mDNS/5353 and ICMP-quoted DNS are
  excluded from ordinary DNS transaction logic. DNS-over-TCP, DoT/DoH and HTTP
  parsing are unsupported. A/AAAA/CNAME/NS/PTR/MX/SRV/TXT are decoded; other RDATA
  is preserved as hex with type/class/TTL. Full DNSSEC validation is not provided.
- TCP is a passive simplified state machine, not an endpoint TCP stack. Sequence
  checks verify a basic handshake. Adjacent duplicate SYN/data signatures provide
  limited retransmission accounting; arbitrary retransmission/reordering, TCP
  simultaneous-open, SYN data and stream reconstruction are outside scope.
- Observed first-seen ARP/resolver identities are not trusted identities. A
  poisoned baseline, unseen requests, routing changes, asymmetric taps, packet
  loss and NAT reduce detection quality. Addresses identify visible endpoints,
  not necessarily physical attackers.
- Counts use bounded rolling approximations described in RULES.md. SYN backlog
  and incomplete ratio are estimates. Hard state caps prevent memory exhaustion
  but can lose detection context; all evictions are reported.
- The analyzer's application state is bounded; output disk usage grows with
  flows, DNS messages, sparse time buckets and alert episodes. Provision disk
  space. Continuous output and backpressure do not imply a bounded total log size.
- Live NIC capture and Slowloris are optional, unimplemented extensions. No claim
  of live drop-rate, live alert latency or HTTP reassembly validation is made.
- No instructor PCAP files or manual reference intervals were supplied. Real
  academic evaluation, threshold calibration, largest-course-capture benchmark
  and data-specific screenshots/report evidence remain pending.
