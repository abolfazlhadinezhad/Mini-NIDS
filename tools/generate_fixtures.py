"""Generate small offline-only Scapy reference captures. No packets are sent."""

import argparse
import json
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, ICMP, IP, TCP, UDP, Dot1Q, Ether, PcapWriter, Raw

BASE = 1_700_000_000
C, S, M, G, R = (
    "10.0.0.10",
    "10.0.0.1",
    "02:00:00:00:00:10",
    "02:00:00:00:00:01",
    "02:00:00:00:00:99",
)


def baseline():
    records = []
    for i in range(4):
        records.append((i, Ether(src=G, dst=M) / ARP(op=2, psrc=S, hwsrc=G, pdst=C, hwdst=M)))
    for i in range(3):
        txid = 100 + i
        q = DNS(id=txid, qd=DNSQR(qname="baseline.test."))
        r = DNS(
            id=txid,
            qr=1,
            aa=1,
            qd=q.qd,
            an=DNSRR(rrname="baseline.test.", ttl=60, rdata="203.0.113.5"),
        )
        records.extend(
            [
                (
                    4 + i,
                    Ether(src=M, dst=G) / IP(src=C, dst=S) / UDP(sport=40000 + i, dport=53) / q,
                ),
                (
                    4.1 + i,
                    Ether(src=G, dst=M) / IP(src=S, dst=C) / UDP(sport=53, dport=40000 + i) / r,
                ),
            ]
        )
    # Normal complete TCP connection.
    records.extend(
        [
            (
                7,
                Ether(src=M, dst=G)
                / IP(src=C, dst=S)
                / TCP(sport=42000, dport=80, flags="S", seq=100),
            ),
            (
                7.1,
                Ether(src=G, dst=M)
                / IP(src=S, dst=C)
                / TCP(sport=80, dport=42000, flags="SA", seq=300, ack=101),
            ),
            (
                7.2,
                Ether(src=M, dst=G)
                / IP(src=C, dst=S)
                / TCP(sport=42000, dport=80, flags="A", seq=101, ack=301),
            ),
            (
                8,
                Ether(src=M, dst=G)
                / IP(src=C, dst=S)
                / TCP(sport=42000, dport=80, flags="FA", seq=101, ack=301),
            ),
            (
                8.1,
                Ether(src=G, dst=M)
                / IP(src=S, dst=C)
                / TCP(sport=80, dport=42000, flags="FA", seq=301, ack=102),
            ),
            # mDNS and unsupported IPv6 EtherType do not become ordinary DNS evidence.
            (
                9,
                Ether(src=M, dst="01:00:5e:00:00:fb")
                / IP(src=C, dst="224.0.0.251")
                / UDP(sport=5353, dport=5353)
                / DNS(qd=DNSQR(qname="device.local.")),
            ),
        ]
    )
    return records


def scenarios():
    arp_attack = [
        (20 + i / 10, Ether(src=R, dst=M) / ARP(op=2, psrc=S, hwsrc=R, pdst=C, hwdst=M))
        for i in range(8)
    ]
    scan = []
    for i in range(25):
        port = 1000 + i
        scan.extend(
            [
                (
                    20 + i / 10,
                    Ether(src=M, dst=G)
                    / IP(src=C, dst=S)
                    / TCP(sport=44000 + i, dport=port, flags="S", seq=100),
                ),
                (
                    20 + i / 10 + 0.01,
                    Ether(src=G, dst=M)
                    / IP(src=S, dst=C)
                    / TCP(sport=port, dport=44000 + i, flags="SA", seq=300, ack=101),
                ),
                (
                    20 + i / 10 + 0.02,
                    Ether(src=M, dst=G)
                    / IP(src=C, dst=S)
                    / TCP(sport=44000 + i, dport=port, flags="R", seq=101, ack=301),
                ),
            ]
        )
    syn = [
        (
            20 + i / 500,
            Ether(src=M, dst=G)
            / IP(src=f"10.1.{i // 250}.{i % 250 + 1}", dst=S)
            / TCP(sport=1000 + i, dport=80, flags="S", seq=i),
        )
        for i in range(1100)
    ]
    query = DNS(id=500, qd=DNSQR(qname="victim.test."))
    dns_attack = [
        (20, Ether(src=M, dst=G) / IP(src=C, dst=S) / UDP(sport=45000, dport=53) / query),
        (
            20.01,
            Ether(src=R, dst=M)
            / IP(src=S, dst=C)
            / UDP(sport=53, dport=45000)
            / DNS(
                id=500, qr=1, qd=query.qd, an=DNSRR(rrname="victim.test.", rdata="198.51.100.99")
            ),
        ),
        (
            20.1,
            Ether(src=G, dst=M)
            / IP(src=S, dst=C)
            / UDP(sport=53, dport=45000)
            / DNS(id=500, qr=1, qd=query.qd, an=DNSRR(rrname="victim.test.", rdata="203.0.113.5")),
        ),
    ]
    return {
        "benign": ([], None),
        "arp": (arp_attack, "ARP Spoofing"),
        "scan": (scan, "Port Scan"),
        "syn": (syn, "SYN Flood"),
        "dns": (dns_attack, "DNS Spoofing"),
    }


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {
        "provenance": "synthetic Scapy scenarios; not course dataset evaluation",
        "captures": [],
    }
    for label, (attack, kind) in scenarios().items():
        path = directory / f"{label}.pcap"
        if path.exists():
            raise FileExistsError(path)
        with PcapWriter(str(path), linktype=1, sync=True) as writer:
            for offset, packet in sorted(baseline() + attack, key=lambda x: x[0]):
                packet.time = BASE + offset
                writer.write(packet)
        references = (
            []
            if kind is None
            else [
                {
                    "incident_id": label + "-synthetic-1",
                    "attack": kind,
                    "start": str(BASE + 20),
                    "end": str(BASE + 30),
                    "dst": C if label == "dns" else S,
                    "evidence": "Synthetic generator schedule; parameters fixed before execution",
                }
            ]
        )
        # ARP src is a MAC; victim is the ARP target IP, not the claimed gateway.
        if label == "arp":
            references[0]["dst"] = C
        (directory / f"{label}.reference.json").write_text(json.dumps(references, indent=2) + "\n")
        manifest["captures"].append(
            {"name": label, "pcap": path.name, "reference": f"{label}.reference.json"}
        )
    # Independent parser edge cases, all built by a separate dissector library.
    with PcapWriter(str(directory / "parser-reference.pcap"), linktype=1, sync=True) as writer:
        packets = [
            Ether(src=M, dst=G)
            / Dot1Q(vlan=77)
            / IP(src=C, dst=S)
            / UDP(sport=40000, dport=123)
            / Raw(b"x"),
            Ether(src=M, dst=G)
            / IP(src=C, dst=S)
            / ICMP(type=3, code=3)
            / IP(src=S, dst=C)
            / UDP(sport=1234, dport=53),
            Ether(src=M, dst=G) / IP(src=C, dst=S, flags="MF", id=42) / Raw(b"x" * 24),
            Ether(src=M, dst=G) / IP(src=C, dst=S, frag=3, id=42) / Raw(b"x" * 8),
        ]
        for i, packet in enumerate(packets):
            packet.time = BASE + i / 10
            writer.write(packet)
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    generate(args.out)
    print(f"Created synthetic-only fixtures in {args.out}")


if __name__ == "__main__":
    main()
