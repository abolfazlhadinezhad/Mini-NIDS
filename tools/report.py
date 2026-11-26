"""Build the engineering report from Markdown plus measured validation evidence."""

import argparse
import csv
import json
import xml.etree.ElementTree as ET
from html import escape
from pathlib import Path

from reportlab.graphics.charts.lineplots import LinePlot
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def build_report(
    source, suite_path, comparison_path, benchmark_path, junit_path, timeseries_path, destination
):
    suite = json.loads(Path(suite_path).read_text())
    comparison = json.loads(Path(comparison_path).read_text())
    benchmark = json.loads(Path(benchmark_path).read_text())
    junit = ET.parse(junit_path).getroot()
    tests = sum(int(s.attrib.get("tests", 0)) for s in junit.iter("testsuite"))
    failures = sum(
        int(s.attrib.get("failures", 0)) + int(s.attrib.get("errors", 0))
        for s in junit.iter("testsuite")
    )
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            "BodyReport",
            parent=styles["BodyText"],
            fontSize=10,
            leading=14,
            spaceAfter=8,
            alignment=TA_LEFT,
        )
    )
    styles.add(
        ParagraphStyle(
            "CellReport", parent=styles["BodyReport"], fontSize=8, leading=10, spaceAfter=0
        )
    )
    for name in ("Title", "Heading1", "Heading2", "Heading3"):
        styles[name].textColor = colors.HexColor("#183b5b")
        styles[name].keepWithNext = True
    story, paragraph = [], []

    def body(text):
        return Paragraph(escape(text), styles["BodyReport"])

    def flush():
        if paragraph:
            story.append(body(" ".join(paragraph)))
            paragraph.clear()

    for line in Path(source).read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            flush()
            prefix, text = line.split(" ", 1)
            style = {1: "Title", 2: "Heading1", 3: "Heading2"}[min(len(prefix), 3)]
            story.append(Paragraph(escape(text), styles[style]))
        elif not line.strip():
            flush()
        else:
            paragraph.append(line)
    flush()

    def table(rows, widths):
        rendered = [
            [Paragraph(escape(str(value)), styles["CellReport"]) for value in row] for row in rows
        ]
        result = Table(rendered, colWidths=widths, repeatRows=1, hAlign="LEFT")
        result.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6edf3")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.6, colors.HexColor("#5f7c94")),
                    ("LINEBELOW", (0, 1), (-1, -1), 0.25, colors.HexColor("#d9e0e6")),
                ]
            )
        )
        return result

    story.extend([PageBreak(), Paragraph("Appendix A. Measured evidence", styles["Heading1"])])
    story.append(
        body(
            f"Validation run: {tests} tests; {failures} failures/errors. "
            "Synthetic results below are not measurements on course captures."
        )
    )
    rows = [["Capture", "Rule alert counts"]]
    for name, counts in suite["matrix"].items():
        rows.append([name, ", ".join(f"{key}: {value}" for key, value in counts.items()) or "None"])
    story.extend([table(rows, [90, 410]), Spacer(1, 12)])
    rows = [["Scenario", "TP incidents / FN", "FP alerts", "First delay (s)"]]
    for name, result in suite["evaluation"].items():
        for _, metrics in result["attacks"].items():
            if metrics["reference_intervals"]:
                rows.append(
                    [
                        name,
                        (
                            f"{metrics['true_positive_intervals']} / "
                            f"{metrics['false_negative_intervals']}"
                        ),
                        metrics["false_alerts"],
                        ", ".join(metrics["first_detection_delay_seconds"].values()),
                    ]
                )
    story.extend([table(rows, [90, 130, 90, 190]), Spacer(1, 12)])
    rows = [["Scan port threshold", "Detected scan incidents", "False alerts", "Delay (s)"]]
    for trial in suite["scan_threshold_sensitivity"]:
        if trial["capture"] == "scan":
            m = trial["metrics"]
            rows.append(
                [
                    trial["scan_ports"],
                    m["true_positive_intervals"],
                    m["false_alerts"],
                    ", ".join(m["first_detection_delay_seconds"].values()) or "No detection",
                ]
            )
    story.extend([table(rows, [120, 130, 90, 160]), Spacer(1, 12)])
    fields = sum(sum(r["field_comparisons"].values()) for r in comparison)
    packets = sum(r["packets_compared"] for r in comparison)
    mismatch = sum(len(r["mismatches_first_100"]) for r in comparison)
    story.append(
        body(
            f"Independent tshark comparison: {packets} packets, {fields} field "
            f"comparisons, {mismatch} recorded mismatches. The mismatch list "
            "is capped at 100 per capture; every compared field is counted."
        )
    )
    story.append(
        body(
            f"Synthetic benchmark: {benchmark['packets']:,} packets in "
            f"{benchmark['seconds_with_tracemalloc_and_output_io']:.3f} seconds, "
            f"{benchmark['packets_per_second']:,.1f} packets/s "
            "including allocation tracing/output. "
            f"Peak Python allocations "
            f"{benchmark['peak_python_allocated_bytes'] / 1048576:.2f} MiB; "
            f"peak process RSS {benchmark['peak_process_rss_bytes'] / 1048576:.2f} MiB. "
            f"Python {benchmark['python']} on {benchmark['platform']}."
        )
    )
    rows = [["State table", "Peak entries", "Configured capacity", "Capacity evictions"]]
    for name, entry in benchmark["state_tables"].items():
        rows.append(
            [name, entry["peak_entries"], entry["capacity"], entry["removals"].get("capacity", 0)]
        )
    story.append(table(rows, [180, 90, 110, 120]))
    story.extend([PageBreak(), Paragraph("Appendix B. Synthetic packet rate", styles["Heading1"])])
    with open(timeseries_path, newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    first = int(rows[0]["epoch_second"])
    points = []
    previous = None
    for row in rows:
        second = int(row["epoch_second"]) - first
        if previous is not None and second - previous > 1:
            points.extend([(previous + 1, 0), (second - 1, 0)])
        points.append((second, int(row["packets"])))
        previous = second
    drawing = Drawing(500, 250)
    plot = LinePlot()
    plot.x, plot.y, plot.width, plot.height = 50, 45, 425, 180
    plot.data = [points]
    plot.lines[0].strokeColor = colors.HexColor("#236b9f")
    plot.lines[0].strokeWidth = 1.5
    plot.xValueAxis.valueMin = plot.yValueAxis.valueMin = 0
    plot.xValueAxis.labels.fontSize = plot.yValueAxis.labels.fontSize = 9
    plot.yValueAxis.visibleGrid = True
    plot.yValueAxis.gridStrokeColor = colors.HexColor("#e1e5e9")
    drawing.add(plot)
    drawing.add(String(190, 8, "Seconds since capture start", fontSize=10))
    drawing.add(String(3, 235, "Packets/s", fontSize=10))
    story.extend(
        [
            KeepTogether(
                [
                    drawing,
                    body(
                        "Synthetic SYN capture: a benign prefix, an empty capture gap, then the "
                        "predetermined SYN-only burst. Empty gap seconds are displayed as zero. "
                        "Attack onset is 20 s; first SYN-1 alert is approximately 22 s. "
                        "The rate chart describes this fixture only."
                    ),
                ]
            )
        ]
    )
    story.append(Paragraph("Appendix C. Reproduction and pending evidence", styles["Heading1"]))
    story.append(
        body(
            "Run pytest, generate_fixtures, evaluate_suite, compare_tshark, and benchmark "
            "as documented in README.md. Rebuild this PDF with tools.report using their "
            "JSON/CSV and JUnit outputs. reports/VALIDATION.md records commands and "
            "immutable source references; REQUIREMENTS.md maps each requirement to code "
            "and tests. The missing instructor captures and their independently labeled "
            "references are still required to finish academic evaluation."
        )
    )

    def decorate(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#617180"))
        canvas.drawString(45, A4[1] - 28, "Mini-NIDS | Engineering report | 2026-11-26")
        canvas.drawRightString(A4[0] - 45, 25, str(document.page))
        canvas.restoreState()

    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("xb") as stream:
        doc = SimpleDocTemplate(
            stream,
            pagesize=A4,
            rightMargin=45,
            leftMargin=45,
            topMargin=48,
            bottomMargin=40,
            title="Mini-NIDS engineering report",
            author="Mini-NIDS project",
        )
        doc.build(story, onFirstPage=decorate, onLaterPages=decorate)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("docs/REPORT.md"))
    for name in ("suite", "comparison", "benchmark", "junit", "timeseries", "out"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    build_report(
        args.source,
        args.suite,
        args.comparison,
        args.benchmark,
        args.junit,
        args.timeseries,
        args.out,
    )
    print(f"Created {args.out}")


if __name__ == "__main__":
    main()
