"""Simulated detonation: predicted behavior, per environment.

"safely detonates files across PC, mobile, and cloud environments"
(the Hub description) - in this source build the detonation is a
STATIC PREDICTION. From the marker evidence, the simulator writes
the telemetry the payload WOULD produce on each profile: process
events, file-system diff, network attempts, persistence mechanism,
API calls. Every event is prefixed SIMULATED, no payload runs, no
packet leaves. HELD payloads are not simulated beyond a one-line
summary - the chamber holds them from even simulated detonation.
"""

from __future__ import annotations

PROFILES = {
    "windows-pc": {
        "label": "PC (Windows)",
        "persistence": "registry Run key (HKCU\\...\\CurrentVersion\\Run)",
        "temp_dir": "C:\\Users\\Public\\",
        "shell": "cmd.exe / powershell",
    },
    "android-mobile": {
        "label": "Mobile (Android)",
        "persistence": "BOOT_COMPLETED broadcast receiver",
        "temp_dir": "/data/local/tmp/",
        "shell": "sh (app sandbox)",
    },
    "linux-cloud": {
        "label": "Cloud (Linux)",
        "persistence": "cron entry / systemd user unit",
        "temp_dir": "/tmp/",
        "shell": "/bin/sh",
    },
}


def simulate(payload: dict, triage_row: dict, profile: str) -> dict:
    env = PROFILES[profile]
    markers = triage_row["markers"]
    all_markers = markers["critical"] + markers["elevated"]
    if triage_row["verdict"] == "HOLD":
        return {
            "profile": profile, "environment": env["label"],
            "status": "HELD - not detonated, even in simulation",
            "events": [f"SIMULATED summary only: payload held for "
                       f"critical marker(s) {markers['critical']}"],
            "executed": False, "network_calls": 0,
        }
    events: list[str] = [f"SIMULATED process start: {payload['name']} under {env['shell']}"]
    fs_diff: list[str] = []
    network: list[str] = []
    api_calls: list[str] = ["SIMULATED trace: process.create, file.open(read self)"]
    if "download" in all_markers or "file-write" in all_markers:
        fs_diff.append(f"SIMULATED write: {env['temp_dir']}payload.bin")
        network.append("SIMULATED network: DNS lookup + HTTPS GET to the payload's URL "
                       "(predicted; no packet sent)")
        api_calls.append("SIMULATED trace: net.connect (blocked in chamber)")
    if "subprocess" in all_markers:
        events.append("SIMULATED child process spawn (predicted from subprocess marker)")
    if "scheduler" in all_markers:
        events.append(f"SIMULATED persistence attempt: {env['persistence']}")
    if "file-delete" in all_markers:
        fs_diff.append("SIMULATED delete: temporary / log files (predicted)")
    if "env-read" in all_markers:
        events.append("SIMULATED environment recon: OS and environment read")
        api_calls.append("SIMULATED trace: sys.uname, env.read")
    if not fs_diff:
        fs_diff.append("SIMULATED fs diff: none predicted")
    if not network:
        network.append("SIMULATED network: none predicted")
    return {
        "profile": profile, "environment": env["label"], "status": "SIMULATED",
        "events": events, "fs_diff": fs_diff, "network": network,
        "api_calls": api_calls, "executed": False, "network_calls": 0,
    }


def detonate_all(payload: dict, triage_row: dict) -> dict:
    return {name: simulate(payload, triage_row, name) for name in PROFILES}
