"""The chamber: static triage before anything is studied.

Every payload is scanned for marker classes:
- CRITICAL markers (eval/exec payloads, reverse shells, key
  listeners, encryption-for-ransom language) -> the payload is HELD:
  recorded, never detonated even in simulation beyond a summary.
- ELEVATED markers (downloads, subprocesses, schedulers, deletes)
  -> study allowed, scored accordingly.
- Anything else -> allowed.

The chamber's invariants, checked by the test suite on every run:
executed is False and network_calls is 0. Always.
"""

from __future__ import annotations

import hashlib
import math
import re

CRITICAL = {
    "eval-exec": r"\b(eval|exec)\s*\(",
    "reverse-shell": r"socket\.socket|connect\s*\(\s*\(|/bin/(?:sh|bash)['\"\s,]+-i|nc\s+-[a-z]*[el]\b",
    "key-listener": r"pynput|keyboard.*listener|GetAsyncKeyState",
    "ransom": r"encrypted.*pay|bitcoin|btc.*wallet|encrypt_all",
    "credential-theft": r"mimikatz|sekurlsa|lsass",
    "base64-payload": r"b64decode|fromhex.*exec|bytes\.fromhex",
}
ELEVATED = {
    "download": r"urlretrieve|urlopen|requests\.(get|post)|curl\s|wget\s",
    "subprocess": r"subprocess|os\.system|popen",
    "scheduler": r"crontab|systemd|schtasks|Run\\\\|launchd",
    "file-delete": r"\brm\s+-|os\.remove|shutil\.rmtree",
    "file-write": r"open\([^)]*['\"]w|urlretrieve",
    "env-read": r"os\.environ|os\.uname|platform\.",
}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def scan_markers(content: str) -> dict:
    lowered = content.lower()
    critical = [name for name, pat in CRITICAL.items()
                if re.search(pat, lowered, re.IGNORECASE)]
    elevated = [name for name, pat in ELEVATED.items()
                if re.search(pat, content, re.IGNORECASE)]
    return {"critical": critical, "elevated": elevated}


def triage(payload: dict) -> dict:
    content = payload.get("content", "")
    markers = scan_markers(content)
    digest = hashlib.sha256(content.encode()).hexdigest()
    held = bool(markers["critical"])
    return {
        "name": payload.get("name", "unnamed"),
        "kind": payload.get("kind", "unknown"),
        "sha256": digest,
        "size_bytes": len(content.encode()),
        "entropy": round(shannon_entropy(content), 3),
        "markers": markers,
        "verdict": "HOLD" if held else "ALLOW",
        "executed": False,
        "network_calls": 0,
    }
