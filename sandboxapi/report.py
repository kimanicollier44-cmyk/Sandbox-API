"""The structured threat report: chamber + simulation + council."""

from __future__ import annotations

import time

from . import chamber, detonate, iocs, scoring
from .brains import council


def build_report(payload: dict) -> dict:
    triage_row = chamber.triage(payload)
    extracted = iocs.extract(payload.get("content", ""))
    score_row = scoring.score(triage_row, extracted)
    synthesis = council.synthesize(triage_row, score_row)
    return {
        "payload": {"name": triage_row["name"], "kind": triage_row["kind"],
                    "sha256": triage_row["sha256"], "size_bytes": triage_row["size_bytes"]},
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "verdict": synthesis["verdict"],
        "threat": score_row,
        "markers": triage_row["markers"],
        "entropy": triage_row["entropy"],
        "iocs": extracted,
        "detonation": detonate.detonate_all(payload, triage_row),
        "council": synthesis,
        "invariants": {"executed": False, "network_calls": 0,
                       "detonation_mode": "static prediction (SIMULATED)"},
    }


def render_markdown(report: dict) -> str:
    p = report["payload"]
    lines = [
        f"# Threat report - {p['name']}",
        "",
        f"Verdict: **{report['verdict']}** · Threat: **{report['threat']['score']}/100 "
        f"({report['threat']['band']})** · sha256 `{p['sha256'][:16]}…` · {p['size_bytes']} bytes",
        f"Score breakdown: {'; '.join(report['threat']['breakdown']) or 'no scoring signals'}",
        f"Markers: critical {report['markers']['critical']} · elevated {report['markers']['elevated']}",
        "",
        "## Detonation (SIMULATED - nothing was executed)",
    ]
    for profile, sim in report["detonation"].items():
        lines.append(f"### {sim['environment']} - {sim['status']}")
        for event in sim["events"]:
            lines.append(f"- {event}")
        for item in sim.get("fs_diff", []):
            lines.append(f"- {item}")
        for item in sim.get("network", []):
            lines.append(f"- {item}")
    if report["iocs"]:
        lines += ["", "## IOCs (extracted statically, never contacted)"]
        for kind, values in report["iocs"].items():
            lines.append(f"- {kind}: {', '.join(values)}")
    lines += ["", "## Council",
              f"Verdict {report['council']['verdict']} - {report['council']['rule']}"]
    for seat in report["council"]["seats"]:
        lines.append(f"- **{seat['model']}**: {seat['note']}")
    lines += ["", f"Invariants: executed = False · network_calls = 0 · "
              f"mode = {report['invariants']['detonation_mode']}"]
    return "\n".join(lines) + "\n"
