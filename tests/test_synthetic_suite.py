import pytest

from tools.evaluate_suite import run_suite
from tools.generate_fixtures import generate


@pytest.mark.filterwarnings("ignore")
def test_every_detector_on_every_synthetic_capture(tmp_path):
    manifest = tmp_path / "fixtures"
    generate(manifest)
    result = run_suite(manifest / "manifest.json", tmp_path / "evaluation", thresholds=(10, 40))
    assert result["matrix"]["benign"] == {}
    assert result["matrix"]["arp"] == {"ARP-1": 1}
    assert result["matrix"]["syn"] == {"SYN-1": 1}
    assert {"DNS-1", "DNS-2", "DNS-3"} <= result["matrix"]["dns"].keys()
    for capture, attack in (
        ("arp", "ARP Spoofing"),
        ("syn", "SYN Flood"),
        ("scan", "Port Scan"),
        ("dns", "DNS Spoofing"),
    ):
        metrics = result["evaluation"][capture]["attacks"][attack]
        assert metrics["true_positive_intervals"] == 1
        assert metrics["false_alerts"] == 0
    sensitivity = [r for r in result["scan_threshold_sensitivity"] if r["capture"] == "scan"]
    assert sensitivity[0]["metrics"]["recall_incident_level"] == 1
    assert sensitivity[1]["metrics"]["recall_incident_level"] == 0
