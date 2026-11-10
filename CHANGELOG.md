# Changelog

## 1.1.0 - 2026-11-10

- MERGE: the fleet chamber came home. sandboxapi/sandbox_api.py is
  the canonical chamber copied VERBATIM (sha256 28b3365c...) from
  MonadDB-RE - the same file Q6G-1TB, LTE-6G and A-C-D-Matrix-FORCE
  carry - now living in the sandbox-api home repo, with a provenance
  check in the test suite and self-checks so it can never drift
  silently. Its payloads seat (sandboxapi/payloads.py) triages 7
  payloads -> 4 ALLOW_STATIC_STUDY / 3 HOLD_IN_CHAMBER, executed
  False, network attempts 0. New CLI: python main.py fleet.
- Verified: pytest 8 passed, CHECKS 22/22.

## 1.0.0 - 2026-11-10

- First source release for credkellar/sandbox-api (the Docker Hub
  image - 8,500+ pulls - previously had no public source repo).
- Chamber triage over synthetic payload descriptors: 12 samples,
  8 ALLOW / 4 HOLD; invariants executed=False, network_calls=0.
- Simulated detonation across PC (Windows), mobile (Android) and
  cloud (Linux) profiles; static IOC extraction; deterministic
  0-100 threat scoring with an explainable breakdown.
- Multi-LLM council: Gemini, Claude, ChatGPT, Codex seats +
  strictest-wins synthesis; 10 HOLD gates.
- Real HTTP API (stdlib): POST /detonate, POST /triage,
  GET /health, GET /samples.
- Verified: pytest 6 passed, CHECKS 19/19, hold-demo exit 2.
