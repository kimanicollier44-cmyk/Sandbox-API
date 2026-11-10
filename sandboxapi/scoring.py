"""Threat scoring: markers, IOCs and entropy -> a 0-100 score.

Deterministic and explainable: every point is accounted for in the
breakdown list, so the report can show its work.
"""

from __future__ import annotations


def score(triage_row: dict, iocs: dict) -> dict:
    points = 0
    why: list[str] = []
    crit = len(triage_row["markers"]["critical"])
    if crit:
        points += 40 * crit
        why.append(f"{crit} critical marker(s) x40")
    elev = len(triage_row["markers"]["elevated"])
    if elev:
        points += 10 * elev
        why.append(f"{elev} elevated marker(s) x10")
    if iocs.get("ips"):
        points += 10
        why.append("external IP present +10")
    if iocs.get("wallets"):
        points += 15
        why.append("wallet string present +15")
    if triage_row["entropy"] > 4.5 and triage_row["size_bytes"] > 40:
        points += 5
        why.append("high entropy content +5")
    total = max(0, min(100, points))
    band = ("CRITICAL" if total >= 80 else "HIGH" if total >= 55 else
            "MEDIUM" if total >= 30 else "LOW" if total > 0 else "CLEAN")
    return {"score": total, "band": band, "breakdown": why}
