"""sandbox-api: cross-platform payload detonation chamber + threat reports.

The source repository for credkellar/sandbox-api (8,500+ Docker Hub
pulls). Payloads arrive as descriptors (name, kind, content text).
The chamber triages them statically, PREDICTS their behavior in a
simulated detonation across PC, mobile and cloud environment
profiles, extracts IOCs, scores the threat, and the multi-LLM
council (Gemini, Claude, ChatGPT, Codex seats) synthesizes the
structured threat report.

Nothing here ever executes a payload: executed is always False and
network calls are always 0. Detonation in this build is a static
prediction, labelled SIMULATED everywhere it appears.
"""

__version__ = "1.1.0"
__all__ = ["__version__"]
