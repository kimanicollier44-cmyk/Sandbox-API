"""Synthesis + HOLD gates: the strictest seat wins, always."""

from __future__ import annotations

from . import seats

HOLD_ACTIONS = {
    "execute_payload": "Payloads are never executed - analysis is static and simulation is predictive.",
    "network_egress": "The chamber makes zero network calls; predicted traffic is text, not packets.",
    "detonate_on_host": "Detonation happens only as simulation inside the chamber model.",
    "bypass_triage": "No payload skips triage, whatever asks.",
    "accept_real_malware": "The chamber studies descriptors and synthetic samples, not live malware binaries.",
    "release_held_payload": "A HELD payload leaves only as a report, never as a file.",
    "fabricate_telemetry": "Simulated events are labelled SIMULATED; inventing real-looking telemetry is fabrication.",
    "advisor_override": "No seat overrides a HOLD; synthesis takes the strictest verdict.",
    "auto_submit_external": "Reports are delivered to the operator, never auto-submitted anywhere.",
    "retention_forever": "Study artifacts follow the operator's retention call, not the tool's.",
}


def decide(action: str) -> dict:
    if action in HOLD_ACTIONS:
        return {"action": action, "verdict": "HOLD", "reason": HOLD_ACTIONS[action],
                "decider": "sandbox-api council (strictest wins)"}
    return {"action": action, "verdict": "PROCEED",
            "reason": "Fits the chamber's static-analysis mandate.",
            "decider": "sandbox-api council (strictest wins)"}


def synthesize(triage_row: dict, score_row: dict) -> dict:
    reviews = [seats.analyze(name, triage_row, score_row) for name in seats.SEATS]
    verdict = "HOLD" if any(r["verdict"] == "HOLD" for r in reviews) else "ALLOW"
    return {"verdict": verdict, "seats": reviews,
            "rule": "strictest verdict wins across all four seats"}
