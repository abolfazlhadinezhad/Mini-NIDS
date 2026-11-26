# Dataset provenance and evaluation procedure

The specification names these exact course-provided slices:

| File | Source in specification | Status |
|---|---|---|
| DoS-SYN-stu.pcap | CIC IoT Dataset 2023 | Not supplied |
| DNSspoofing-stu.pcap | CIC IoT Dataset 2023 | Not supplied |
| ARPspoofing-stu.pcap | CIC IoT Dataset 2023 | Not supplied |
| portScan-stu.pcap | CIC-IDS2017 Friday | Not supplied |
| DoS-slowloris-stu.pcap | CIC-IDS2017 Wednesday, optional | Not supplied |

Public provenance pages:

- https://www.unb.ca/cic/datasets/iotdataset-2023.html
- https://www.unb.ca/cic/datasets/ids-2017.html

The public full captures are not interchangeable with instructor slices. Do not
download a large dataset and rename it as a student capture. No traffic is
transmitted by this repository's fixture utilities.

## Required real-capture workflow

1. Place course captures in ignored datasets/. Hash each file with SHA-256 and
   record size, timestamp range, snaplen and capture precision.
2. Inspect each whole file independently in Wireshark/tshark. Identify a benign
   interval, attack start/end, visible source/target, probe types and victim
   response, NAT interpretation, truncation and capture gaps.
3. Write reference JSON BEFORE tuning detector thresholds. Use Unix capture
   timestamp strings; do not copy full-dataset wall-clock labels without mapping
   capture offsets/timezones. Record the display filter, frame numbers and reason
   for each label in evidence.
4. Measure baseline pps/SYN rates, fanout, handshake completions, ARP changes and
   DNS resolver behavior. Choose configuration on development captures/intervals,
   then freeze it for held-out evaluation.
5. Run every detector on every capture via tools.evaluate_suite. Inspect every
   nonzero off-diagonal result, including ARP alerts in DNS spoofing captures:
   a multistage attack can make those correct.
6. Report alert-level precision and incident-level recall separately. TP interval:
   at least one correct-type matching alert; FN: a reference interval with none.
   FP alert: wrong type/participants or outside the labeled interval plus explicit
   margin. Repeated correct alerts remain true alerts, but one incident is only
   one detected interval. Undefined ratios are null, never invented zero/one.
7. Report delay from manually labeled onset to earliest correct alert using
   capture time; retain any negative delay allowed by a declared margin.
8. Change at least one threshold, report FP/recall/delay tradeoff, explain every
   false positive using protocol evidence, and benchmark the largest supplied
   capture with peak process memory and throughput.

Reference format (example addresses/times only):

    [
      {
        "incident_id": "scan-1",
        "attack": "Port Scan",
        "start": "1700000020.000000",
        "end": "1700000030.000000",
        "src": "10.0.0.10",
        "dst": "10.0.0.1",
        "evidence": "Analyst: tshark filter, frame range, open-port follow-up"
      }
    ]

src/dst constraints are optional. SYN flood may have spoofed/distributed sources,
so label the victim rather than trusting every source. ARP-1 src is the claimant
MAC and dst the ARP target IP. DNS alert src is the claimed resolver IP; L2
evidence is essential for attribution.

## Synthetic evidence

tools.generate_fixtures builds five small independent Scapy captures: benign,
ARP conflict, SYN-style port scan, distributed-source SYN flood, and a two-stage
DNS race. Every attack capture contains the same benign prefix. Parameters and
reference intervals are predetermined. These tests establish software behavior
on known inputs, not recall/precision on real networks. Synthetic truth is not
manual Wireshark ground truth for the missing course files.
