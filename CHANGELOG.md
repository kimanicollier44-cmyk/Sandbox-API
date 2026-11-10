# Changelog

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
