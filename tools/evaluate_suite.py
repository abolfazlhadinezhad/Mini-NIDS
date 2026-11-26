"""Run every detector against every manifest capture, with scan threshold sensitivity."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

from mininids.capture import PcapReader
from mininids.config import Config
from mininids.engine import Engine
from mininids.evaluation import evaluate, load_references
from mininids.output import Outputs


def run_capture(path, destination, config):
    outputs = Outputs(destination)
    engine = Engine(outputs, config)
    try:
        with path.open("rb") as source:
            for record in PcapReader(source, config.max_packet_bytes):
                engine.process(record)
        summary = engine.finish()
        outputs.json("stats.json", summary)
    finally:
        outputs.close()
    return summary


def run_suite(manifest_path, directory, thresholds=(10, 20, 40)):
    manifest_path, directory = Path(manifest_path), Path(directory)
    manifest = json.loads(manifest_path.read_text())
    directory.mkdir(parents=True, exist_ok=True)
    result = {
        "provenance": manifest.get("provenance", "analyst-supplied"),
        "matrix": {},
        "evaluation": {},
        "scan_threshold_sensitivity": [],
    }
    for capture in manifest["captures"]:
        name = capture["name"]
        if Path(name).name != name or name in (".", ".."):
            raise ValueError("capture name must be a simple directory name")
        pcap = manifest_path.parent / capture["pcap"]
        refs = load_references(manifest_path.parent / capture["reference"])
        config = (
            Config.from_file(manifest_path.parent / capture["config"])
            if capture.get("config")
            else Config()
        )
        base = directory / name
        summary = run_capture(pcap, base, config)
        result["matrix"][name] = summary["alerts_emitted"]
        result["evaluation"][name] = evaluate(base / "alerts.csv", refs)
        for threshold in thresholds:
            trial = directory / f"{name}-scan-{threshold}"
            varied = replace(config, scan_ports=threshold)
            run_capture(pcap, trial, varied)
            result["scan_threshold_sensitivity"].append(
                {
                    "capture": name,
                    "scan_ports": threshold,
                    "metrics": evaluate(trial / "alerts.csv", refs)["attacks"]["Port Scan"],
                }
            )
    with (directory / "suite.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    run_suite(args.manifest, args.out)
    print(f"Evaluation saved to {args.out / 'suite.json'}")


if __name__ == "__main__":
    main()
