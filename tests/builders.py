"""Small deterministic wire fixtures; never transmit packets."""

import ipaddress
import struct

CLIENT = "10.0.0.10"
SERVER = "10.0.0.1"
MAC = "02:00:00:00:00:10"
GATEWAY = "02:00:00:00:00:01"
ROGUE = "02:00:00:00:00:99"


def ip(value):
    return ipaddress.ip_address(value).packed


def mac(value):
    return bytes.fromhex(value.replace(":", ""))


def ethernet(payload, etype=0x0800, src=MAC, dst=GATEWAY, vlan=None):
    head = mac(dst) + mac(src)
    if vlan is not None:
        return head + struct.pack("!HHH", 0x8100, vlan, etype) + payload
    return head + struct.pack("!H", etype) + payload


def ipv4(payload, proto=6, src=CLIENT, dst=SERVER, flags_offset=0, total=None, ttl=64):
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            total or 20 + len(payload),
            7,
            flags_offset,
            ttl,
            proto,
            0,
            ip(src),
            ip(dst),
        )
        + payload
    )


def tcp(sport=40000, dport=80, flags=2, seq=100, ack=0, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 8192, 0, 0) + payload


def udp(payload=b"", sport=40000, dport=53):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def arp(sender_ip=SERVER, sender_mac=GATEWAY, target_ip=CLIENT, target_mac=MAC, op=2):
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
        + mac(sender_mac)
        + ip(sender_ip)
        + mac(target_mac)
        + ip(target_ip)
    )


def name(value):
    return b"".join(bytes([len(p)]) + p.encode() for p in value.rstrip(".").split(".")) + b"\0"


def dns(txid=123, response=False, address="203.0.113.5", qname="example.test", ttl=60):
    question = name(qname) + struct.pack("!HH", 1, 1)
    head = struct.pack("!6H", txid, 0x8180 if response else 0x0100, 1, int(response), 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + ip(address)
    return head + question + (answer if response else b"")


def pcap(records, endian="<", nano=False, linktype=1, snaplen=65535):
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    result = struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)
    for ns, data, original in records:
        fraction = (ns % 1_000_000_000) // (1 if nano else 1000)
        result += (
            struct.pack(
                endian + "IIII",
                ns // 1_000_000_000,
                fraction,
                len(data),
                original if original is not None else len(data),
            )
            + data
        )
    return result
