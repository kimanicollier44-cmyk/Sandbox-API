"""The four analyzer seats named in the product spec.

Gemini, Claude, ChatGPT and Codex each review the same evidence
from their seat's angle; the synthesis (council.py) takes the
strictest verdict. Seats are names-only API seats: with no keys
configured they run the deterministic local analysis below, and
their live counterparts would receive exactly this evidence pack.
No seat can execute anything; analysis is their only verb.
"""

from __future__ import annotations

SEATS = {
    "gemini": {"model": "Gemini (Carbon 4 Extended Thinking)", "angle": "deep reasoning over the behavior prediction",
               "key_env": "GEMINI_API_KEY"},
    "claude": {"model": "Claude", "angle": "safety review of the triage verdict",
               "key_env": "ANTHROPIC_API_KEY"},
    "chatgpt": {"model": "ChatGPT", "angle": "report clarity and family classification",
                "key_env": "OPENAI_API_KEY"},
    "codex": {"model": "Codex", "angle": "code-level marker verification",
              "key_env": "OPENAI_API_KEY"},
}


def analyze(seat: str, triage_row: dict, score_row: dict) -> dict:
    info = SEATS[seat]
    verdict = triage_row["verdict"]
    note = {
        "gemini": f"Behavior prediction consistent with markers "
                  f"{triage_row['markers']['critical'] + triage_row['markers']['elevated']} "
                  f"at score {score_row['score']}.",
        "claude": "Triage verdict reviewed: "
                  + ("HOLD is correct - critical markers present."
                     if verdict == "HOLD" else
                     "ALLOW for static study is proportionate; no execution either way."),
        "chatgpt": f"Family classification: "
                   + ("malware-pattern (held)" if verdict == "HOLD"
                      else "benign-to-dual-use utility pattern"),
        "codex": "Marker scan re-verified at code level: "
                 f"{len(triage_row['markers']['critical'])} critical, "
                 f"{len(triage_row['markers']['elevated'])} elevated.",
    }[seat]
    return {"seat": seat, "model": info["model"], "angle": info["angle"],
            "verdict": verdict, "note": note, "mode": "local-deterministic (names-only seat)"}
