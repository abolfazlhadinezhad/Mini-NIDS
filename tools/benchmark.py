"""Measure a real single-pass analysis; generated captures are explicitly synthetic."""

import argparse
import ctypes
import json
import os
import platform
import struct
import time
import tracemalloc
from pathlib import Path

from mininids.capture import PcapReader
from mininids.config import Config
from mininids.engine import Engine
from mininids.output import Outputs


def peak_rss():
    if os.name == "nt":
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t)
                for name in ("peak", "working", "qpp", "qp", "qnp", "qn", "page", "pagepeak")
            ]

        counters = Counters()
        counters.cb = ctypes.sizeof(counters)
        current = ctypes.windll.kernel32.GetCurrentProcess
        current.restype = wintypes.HANDLE
        memory = ctypes.windll.psapi.GetProcessMemoryInfo
        memory.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        if not memory(current(), ctypes.byref(counters), counters.cb):
            raise OSError("GetProcessMemoryInfo failed")
        return counters.peak
    import resource

    value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return value if platform.system() == "Darwin" else value * 1024


def generate(path, packets):
    with path.open("xb") as stream:
        stream.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i in range(packets):
            # Distinct bidirectional tuples stress eviction, not packet buffering.
            frame = bytes.fromhex("0200000000010200000000100800")
            src = struct.pack("!I", 0x0A000001 + (i % 0xFFFFFE))
            frame += struct.pack(
                "!BBHHHBBH4s4s", 0x45, 0, 40, i % 65536, 0, 64, 6, 0, src, b"\x0a\xff\xff\xfe"
            )
            frame += struct.pack("!HHIIBBHHH", 1024 + i % 60000, 80, i, 0, 0x50, 2, 8192, 0, 0)
            ns = 1_700_000_000_000_000_000 + i * 10_000
            stream.write(
                struct.pack(
                    "<IIII",
                    ns // 1_000_000_000,
                    (ns % 1_000_000_000) // 1000,
                    len(frame),
                    len(frame),
                )
            )
            stream.write(frame)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path)
    parser.add_argument("--generate-packets", type=int, default=0)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--config", type=Path)
    args = parser.parse_args()
    if bool(args.pcap) == bool(args.generate_packets):
        parser.error("choose --pcap or positive --generate-packets")
    if args.generate_packets < 0:
        parser.error("packet count must be positive")
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.pcap
    if args.generate_packets:
        path = args.out / "synthetic-benchmark.pcap"
        generate(path, args.generate_packets)
    config = Config.from_file(args.config) if args.config else Config()
    outputs = Outputs(args.out / "analysis")
    engine = Engine(outputs, config)
    tracemalloc.start()
    start = time.perf_counter()
    try:
        with path.open("rb") as source:
            for record in PcapReader(source, config.max_packet_bytes):
                engine.process(record)
        stats = engine.finish()
        outputs.json("stats.json", stats)
    finally:
        outputs.close()
    elapsed = time.perf_counter() - start
    _, python_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    result = {
        "provenance": "synthetic" if args.generate_packets else "user supplied",
        "capture": str(path),
        "capture_bytes": path.stat().st_size,
        "packets": stats.get("packets", 0),
        "seconds_with_tracemalloc_and_output_io": elapsed,
        "packets_per_second": stats.get("packets", 0) / elapsed,
        "peak_python_allocated_bytes": python_peak,
        "peak_process_rss_bytes": peak_rss(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "state_tables": stats["state_tables"],
        "measurement_note": (
            "Includes CSV/JSONL output and tracemalloc overhead; RSS is process peak."
        ),
    }
    with (args.out / "benchmark.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps({k: v for k, v in result.items() if k != "state_tables"}, indent=2))


if __name__ == "__main__":
    main()
