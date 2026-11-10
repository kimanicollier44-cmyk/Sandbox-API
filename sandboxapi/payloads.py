"""Payload triage through the fleet chamber (merged seat).

Every payload in this set passes through the chamber first. The
chamber (sandboxapi/sandbox_api.py, copied VERBATIM - sha256
28b3365c0466027079a4985520840f6532d7d9a0c5b4239b840e561f06de54b0 -
from Darion's MonadDB-RE implementation of his credkellar/sandbox-api
merge, the same file Q6G-1TB, LTE-6G and A-C-D-Matrix-FORCE carry)
treats each payload as DATA ONLY: never executed, network attempts
always 0.

This module supplies the payload set and the static analyser the
chamber runs: a marker scan. Dangerous markers (eval/exec, shell,
raw sockets, pipe-to-shell) -> HOLD_IN_CHAMBER. Clean payloads ->
ALLOW_STATIC_STUDY.
"""

from __future__ import annotations

from .sandbox_api import detonate_static

DANGER_MARKERS = {
    "eval(": "eval_call",
    "exec(": "exec_call",
    "os.system": "shell_command",
    "subprocess": "subprocess",
    "socket.connect": "raw_socket_connect",
    "| sh": "pipe_to_shell",
    "rm -rf": "destructive_delete",
}

PAYLOADS: list[dict] = [
    {"name": "detonation-config",
     "data": b'{"env": "linux-cloud", "capture": ["telemetry", "fs-diff", "api-trace"]}'},
    {"name": "threat-report-draft",
     "data": b'{"title": "weekly summary", "findings": 3, "highest": "LOW"}'},
    {"name": "ioc-list-csv",
     "data": b'indicator,type\nupdates.example.com,domain\n203.0.113.10,ip\n'},
    {"name": "sample-log-lines",
     "data": b'INFO boot ok\nINFO scan complete\nWARN none\n'},
    {"name": "payload-eval-marker",
     "data": b'{"action": "run", "code": "eval(user_input)"}'},
    {"name": "payload-socket-attempt",
     "data": b'{"action": "exfil", "code": "socket.connect((host, 4444))"}'},
    {"name": "payload-shell-command",
     "data": b'{"action": "setup", "code": "os.system(cleanup)"}'},
]


def analyse_payload(data: bytes) -> dict:
    """Static marker scan. This is the function the chamber runs."""
    text = data.decode("utf-8", errors="replace")
    fingerprints = [label for marker, label in DANGER_MARKERS.items() if marker in text]
    return {
        "fingerprints": fingerprints,
        "node_count": len(text.splitlines()) or 1,
        "bytes_scanned": len(data),
        "verdict": "HOLD_IN_CHAMBER" if fingerprints else "ALLOW_STATIC_STUDY",
    }


def run_chamber() -> dict:
    """Run every payload through one fresh chamber each; summarise."""
    runs = []
    for payload in PAYLOADS:
        result = detonate_static(payload["name"], payload["data"], analyse_payload)
        report, telemetry = result["report"], result["telemetry"]
        runs.append({
            "name": payload["name"],
            "verdict": report["verdict"],
            "fingerprints": report["fingerprints"],
            "executed_sample_code": telemetry["executed_sample_code"],
            "network_attempts": telemetry["network_attempts"],
            "sha256": telemetry["sha256"][:16],
        })
    held = [r for r in runs if r["verdict"] == "HOLD_IN_CHAMBER"]
    return {
        "chamber": "sandbox-api (static, never executes)",
        "total": len(runs),
        "allowed": len(runs) - len(held),
        "held": len(held),
        "all_executed": any(r["executed_sample_code"] for r in runs),
        "total_network_attempts": sum(r["network_attempts"] for r in runs),
        "runs": runs,
    }
