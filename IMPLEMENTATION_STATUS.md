# Implementation status

Updated: 2026-11-26. Mandatory offline implementation delivered; academic
real-dataset evaluation remains blocked by missing inputs.

- Repository inspected: clean `main`, baseline 0fe5f48; correct origin and identity.
- All 22 specification pages read and visually inspected, including tables,
  evaluation, report questions, grading and final submission requirements.
- Existing virtual environment preserved; Python 3.13 and test tools available.
- Mandatory parsers, bounded state, four attack families, CLI, outputs and
  evaluation merged into main at 1d80b4c; origin/main SHA verified equal.
- 127 tests pass locally on Python 3.13.13; Ruff lint and format checks pass.
- GitHub Actions run 45802235847 at main merge 1d80b4c passed all five jobs:
  Windows/Linux Python 3.11/3.13 tests/builds and independent Linux tshark.
- Local tshark 4.6.10: 1,270 packets / 27,652 fields; zero mismatches.
- Five synthetic scenarios: benign has no alerts; four attacks detected;
  threshold sensitivity and detector/capture matrix generated.
- Streaming stress run: 100,000 generated packets; all table caps respected.
- Four mandatory student PCAPs and optional Slowloris capture: unavailable.
- tshark is available as a workspace-local ignored portable tool; no capture
  driver was installed and no attack/replay packets were transmitted.
- Academic dataset metrics: **not measured**, no claim of validated accuracy.

## Deliverables

README/configuration; requirements/architecture/plan/Git workflow; rule catalog,
dataset workflow, limitations; report source and generated six-page PDF; tests,
CI, benchmark and reference tools. Ignored outputs/ retains full synthetic
per-capture exports. Small reports/evidence/ summaries are intentional project
assets without payloads, secrets or course datasets.

## Outstanding academic work

E01: independently label exact course captures and measure benign baselines.
E03/E04: real-capture precision/recall/delay, false-positive investigation,
cross-file matrix and threshold calibration. E05: largest-course-capture
benchmark. R01: add real-data screenshots and findings to the report.
Synthetic metrics do not fulfill these external evidence requirements.

Optional X01 live monitoring and X02 Slowloris are deferred. REQUIREMENTS.md maps
each requirement to its implementation, tests, validation status and evidence.
