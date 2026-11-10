"""Static IOC extraction: indicators read from the payload text.

URLs, domains, IPs, file paths, registry keys and wallet-shaped
strings - extracted as strings, never contacted, never resolved.
"""

from __future__ import annotations

import re

PATTERNS = {
    "urls": r"https?://[^\s'\"\)\]]+",
    "ips": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domains": r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|example|xyz|top|info)\b",
    "paths": r"(?:/[\w.-]+){2,}|[A-Za-z]:\\[\w\\.-]+",
    "registry": r"HKEY_[\w\\]+|CurrentVersion\\Run\w*",
    "wallets": r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{20,}\b",
}


def extract(content: str) -> dict:
    out: dict[str, list[str]] = {}
    for name, pattern in PATTERNS.items():
        found = sorted(set(re.findall(pattern, content)))
        if name == "domains":
            found = [d for d in found
                     if not any(d in u for u in out.get("urls", []))]
        if found:
            out[name] = found[:12]
    return out
