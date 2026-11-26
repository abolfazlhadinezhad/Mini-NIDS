# Mini-NIDS engineering plan

Specification: local `Mini-NIDS.pdf`, all 22 pages reviewed as text and rendered
pages on 2026-11-26. Document instructions are academic requirements, not
authorization to execute the attack/replay examples in that document.

## Delivery sequence

1. Preserve baseline history and files; establish requirements and Git workflow.
2. Implement manually decoded Ethernet/VLAN, ARP, IPv4, ICMP, TCP, UDP, DNS;
   independently test valid, malformed, fragmented, and capture-truncated packets.
3. Implement streaming capture input, bounded state, TCP transitions, ARP and DNS
   correlation, flow exports, and capture-time windows.
4. Add independent contextual ARP, vertical TCP/UDP scan, destination SYN flood,
   and three-layer DNS rules, with measured evidence and immediate first alerts.
5. Integrate CLI, streaming outputs, statistics, evaluation, reference comparison,
   synthetic multi-capture scenarios, threshold sweep, CI, documentation and report.
6. Consider optional live input/Slowloris only after mandatory offline tests pass.
7. Run full validation, update traceability, merge into main, push and verify SHA.

Each completed logical unit is tested, linted, reviewed, committed and pushed.
Missing course captures must never be replaced by synthetic data in claims about
academic detection accuracy. Reference labels must be analyst supplied, fixed
before threshold tuning, and expressed in capture timestamps.

## Execution checkpoint

Steps 1-5: mandatory software implemented, tested, independently compared and
documented. Real-capture evaluation remains pending because the instructor
slices/reference labels are unavailable. Step 6: optional work deferred.
Step 7: completed main integration, push and independent SHA/CI verification;
see reports/VALIDATION.md. External academic evidence remains explicitly open.

## Acceptance gates

- Tests and lint pass; CLI runs from a fresh installation; no automatic dissection
  in core parsing; bounded tables/windows; no capture-wide packet retention.
- All four mandatory rules fire on deterministic attack scenarios and suppress
  documented benign analogues. Independent dissector results are compared where
  the environment permits. Synthetic and real-capture evidence are distinguished.
- README, rule catalog, traceability, flow/DNS/alert/statistics outputs,
  evaluation tools and PDF engineering report are present.
- Instructor-provided dataset evaluation remains explicitly pending until all
  four named course captures and manual reference intervals are available.
