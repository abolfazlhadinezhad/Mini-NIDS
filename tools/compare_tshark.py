"""Streaming independent field comparison against a user-supplied tshark executable."""

import argparse
import csv
import json
import struct
import subprocess
import tempfile
from collections import Counter
from decimal import Decimal
from pathlib import Path

from mininids.capture import PcapReader
from mininids.protocols import parse_packet

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.len",
    "frame.cap_len",
    "eth.src",
    "eth.dst",
    "eth.type",
    "vlan.id",
    "arp.opcode",
    "arp.src.hw_mac",
    "arp.src.proto_ipv4",
    "arp.dst.hw_mac",
    "arp.dst.proto_ipv4",
    "ip.src",
    "ip.dst",
    "ip.ttl",
    "ip.proto",
    "ip.len",
    "ip.id",
    "ip.flags",
    "ip.frag_offset",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.flags",
    "tcp.window_size_value",
    "tcp.len",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "icmp.type",
    "icmp.code",
    "dns.id",
    "dns.flags.response",
    "dns.qry.name",
    "dns.qry.type",
    "dns.a",
    "dns.resp.ttl",
)


def expected_fields(packet):
    r, e = packet.record, packet.ethernet
    values = {
        "frame.number": r.index,
        "frame.time_epoch": r.timestamp,
        "frame.len": r.original_length,
        "frame.cap_len": len(r.data),
    }
    if e:
        values.update(
            {
                "eth.src": e.src,
                "eth.dst": e.dst,
                "eth.type": struct.unpack_from("!H", r.data, 12)[0],
            }
        )
        if e.vlan_tags:
            values["vlan.id"] = e.vlan_tags[0] & 0xFFF
    if packet.arp:
        a = packet.arp
        values.update(
            {
                "arp.opcode": a.operation,
                "arp.src.hw_mac": a.sender_mac,
                "arp.src.proto_ipv4": a.sender_ip,
                "arp.dst.hw_mac": a.target_mac,
                "arp.dst.proto_ipv4": a.target_ip,
            }
        )
    if packet.ip:
        ip = packet.ip
        values.update(
            {
                "ip.src": ip.src,
                "ip.dst": ip.dst,
                "ip.ttl": ip.ttl,
                "ip.proto": ip.protocol,
                "ip.len": ip.total_length,
                "ip.id": ip.identification,
                "ip.flags": ip.flags,
                "ip.frag_offset": ip.fragment_offset // 8,
            }
        )
    if packet.tcp:
        t = packet.tcp
        values.update(
            {
                "tcp.srcport": t.src_port,
                "tcp.dstport": t.dst_port,
                "tcp.seq_raw": t.sequence,
                "tcp.ack_raw": t.acknowledgment,
                "tcp.flags": t.flags,
                "tcp.window_size_value": t.window,
                "tcp.len": t.payload_length,
            }
        )
    if packet.udp:
        u = packet.udp
        values.update(
            {"udp.srcport": u.src_port, "udp.dstport": u.dst_port, "udp.length": u.length}
        )
    if packet.icmp:
        values.update({"icmp.type": packet.icmp.type, "icmp.code": packet.icmp.code})
    if packet.dns:
        d = packet.dns
        values.update({"dns.id": d.transaction_id, "dns.flags.response": int(d.response)})
        if d.questions:
            values["dns.qry.name"] = d.questions[0].name.rstrip(".")
            values["dns.qry.type"] = d.questions[0].type
        if d.answers:
            values["dns.resp.ttl"] = d.answers[0].ttl
        addresses = [r.value for r in d.answers if r.type == 1]
        if addresses:
            values["dns.a"] = addresses[0]
    return values


def compare(pcap, executable):
    args = [
        str(executable),
        "-n",
        "-r",
        str(pcap),
        "-o",
        "ip.defragment:FALSE",
        "-o",
        "tcp.relative_sequence_numbers:FALSE",
        "-T",
        "fields",
        "-E",
        "occurrence=f",
        "-E",
        "quote=d",
    ]
    for field in FIELDS:
        args.extend(["-e", field])
    checked, mismatches, count = Counter(), [], 0
    # Explicit directory keeps project temporary assets within the workspace.
    with tempfile.TemporaryFile(dir=Path(pcap).parent) as err, open(pcap, "rb") as source:
        process = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=err, text=True, encoding="utf-8"
        )
        try:
            rows = csv.reader(process.stdout, delimiter="\t")
            for record in PcapReader(source):
                row = next(rows, None)
                if row is None or len(row) != len(FIELDS):
                    if row is None:
                        process.wait(timeout=30)
                        err.seek(0)
                        detail = err.read().decode(errors="replace").strip()
                    else:
                        detail = f"expected {len(FIELDS)} fields, got {len(row)}: {row!r}"
                    raise ValueError(f"invalid tshark output at packet {record.index}: {detail}")
                actual = dict(zip(FIELDS, row, strict=True))
                for field, expected in expected_fields(parse_packet(record)).items():
                    raw = actual[field]
                    if isinstance(expected, int):
                        if raw in ("True", "False"):
                            observed = int(raw == "True")
                        else:
                            observed = int(raw, 16 if raw.startswith("0x") else 10) if raw else None
                    elif isinstance(expected, Decimal):
                        observed = Decimal(raw) if raw else None
                    else:
                        observed = raw.lower() if field == "dns.qry.name" else raw
                    checked[field] += 1
                    if observed != expected and len(mismatches) < 100:
                        mismatches.append(
                            {
                                "packet": record.index,
                                "field": field,
                                "expected": str(expected),
                                "tshark": raw,
                            }
                        )
                count += 1
            if next(rows, None) is not None:
                raise ValueError("tshark emitted additional packet rows")
            if process.wait(timeout=30):
                err.seek(0)
                raise RuntimeError(err.read().decode(errors="replace"))
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait()
    return {
        "capture": str(pcap),
        "packets_compared": count,
        "field_comparisons": dict(checked),
        "mismatches_first_100": mismatches,
        "passed": not mismatches,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", required=True, type=Path)
    parser.add_argument("--pcap", required=True, type=Path, nargs="+")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    results = [compare(path, args.tshark) for path in args.pcap]
    with args.out.open("x", encoding="utf-8") as stream:
        json.dump(results, stream, indent=2)
        stream.write("\n")
    print(f"Compared {sum(r['packets_compared'] for r in results)} packets")
    return 0 if all(r["passed"] for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
