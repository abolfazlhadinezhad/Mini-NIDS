"""Command-line entry point; a failed run is never labeled complete."""

import argparse
import sys
import time
from pathlib import Path

from . import __version__
from .capture import PcapReader
from .config import Config
from .engine import Engine
from .errors import CaptureError
from .output import Outputs


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Mini-NIDS manual streaming Ethernet PCAP analysis"
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--pcap", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True, help="fresh output directory")
    parser.add_argument("--config", type=Path, help="JSON overrides for detection/state thresholds")
    args = parser.parse_args(argv)
    outputs = engine = None
    started = time.perf_counter()
    try:
        config = Config.from_file(args.config) if args.config else Config()
        with args.pcap.open("rb") as source:
            reader = PcapReader(source, config.max_packet_bytes)
            outputs = Outputs(args.out)
            engine = Engine(outputs, config)
            status = "complete"
            error = None
            try:
                for record in reader:
                    engine.process(record)
            except KeyboardInterrupt:
                status, error = "interrupted", "user interrupted processing"
            except (CaptureError, OSError) as exc:
                status, error = "failed", str(exc)
            summary = engine.finish()
            elapsed = time.perf_counter() - started
            summary.update(
                {
                    "processing_seconds": elapsed,
                    "packets_per_processing_second": summary.get("packets", 0) / elapsed,
                    "snaplen": reader.snaplen,
                    "linktype": reader.linktype,
                }
            )
            outputs.json("stats.json", summary)
            outputs.json(
                "run.json",
                {
                    "version": __version__,
                    "input": str(args.pcap.resolve()),
                    "status": status,
                    "error": error,
                    "config": config.as_dict(),
                    "mode": "offline",
                    "timestamp_unit": "Unix seconds; decimal nanosecond precision",
                    "checksum_policy": "raw values retained; no checksum-based attack verdicts",
                    "fragment_policy": "counted; transport dissection skipped; no reassembly",
                },
            )
            if status != "complete":
                print(
                    f"mini-nids: {error}; partial outputs retained in {args.out}", file=sys.stderr
                )
                return 130 if status == "interrupted" else 2
            print(
                f"Analyzed {summary.get('packets', 0)} packets; "
                f"{sum(summary['alerts_emitted'].values())} alerts; outputs: {args.out}"
            )
            return 0
    except (OSError, CaptureError, ValueError) as exc:
        print(f"mini-nids: {exc}", file=sys.stderr)
        return 2
    finally:
        if outputs:
            outputs.close()


if __name__ == "__main__":
    raise SystemExit(main())
