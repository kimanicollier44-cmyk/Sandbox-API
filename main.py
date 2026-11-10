#!/usr/bin/env python3
"""sandbox-api - cross-platform detonation chamber + threat reports.

Usage:
  python main.py demo              triage + reports for the synthetic sample set
  python main.py triage <sample>   one sample's triage row
  python main.py detonate <sample> one sample's full threat report (markdown)
  python main.py serve [port]      run the HTTP API (default 8771)
  python main.py checks            self-checks
  python main.py hold-demo         show a HOLD verdict (exit 2)
"""

from __future__ import annotations

import json
import sys

from sandboxapi import __version__, chamber, report, samples
from sandboxapi.brains import council


def checks() -> list[tuple[str, bool, str]]:
    out: list[tuple[str, bool, str]] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        out.append((name, bool(cond), detail))

    check("version", __version__ == "1.0.0", __version__)
    rows = [chamber.triage(s) for s in samples.SAMPLES]
    check("12 samples", len(rows) == 12)
    check("triage 8 allow / 4 hold",
          sum(r["verdict"] == "ALLOW" for r in rows) == 8
          and sum(r["verdict"] == "HOLD" for r in rows) == 4)
    check("held set is the dangerous four",
          {r["name"] for r in rows if r["verdict"] == "HOLD"}
          == {"eval-loader", "reverse-shell", "key-listener", "ransom-note"})
    check("shebang scripts not held",
          chamber.triage({"name": "x", "kind": "shell",
                          "content": "#!/bin/sh\necho hi\n"})["verdict"] == "ALLOW")
    check("invariants on every row",
          all(r["executed"] is False and r["network_calls"] == 0 for r in rows))
    rep = report.build_report(samples.by_name("reverse-shell"))
    check("report verdict HOLD", rep["verdict"] == "HOLD")
    check("report threat >= 60", rep["threat"]["score"] >= 60, str(rep["threat"]["score"]))
    check("report IOC ip extracted", "203.0.113.66" in rep["iocs"].get("ips", []))
    check("held payload not simulated",
          all(sim["status"].startswith("HELD") for sim in rep["detonation"].values()))
    rep2 = report.build_report(samples.by_name("auto-updater"))
    check("allowed payload simulated on 3 profiles",
          len(rep2["detonation"]) == 3
          and all(sim["status"] == "SIMULATED" for sim in rep2["detonation"].values()))
    check("simulation predicts network for updater",
          any("DNS lookup" in n for sim in rep2["detonation"].values()
              for n in sim.get("network", [])))
    check("markdown renders", "Threat report" in report.render_markdown(rep2))
    check("council 4 seats", len(rep2["council"]["seats"]) == 4)
    check("council HOLD execute", council.decide("execute_payload")["verdict"] == "HOLD")
    check("council HOLD egress", council.decide("network_egress")["verdict"] == "HOLD")
    check("council PROCEED report", council.decide("build_report")["verdict"] == "PROCEED")
    from sandboxapi import server as srv
    import threading
    import urllib.request
    server = srv.serve(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=5) as resp:
            health = json.loads(resp.read())
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/detonate",
            data=json.dumps(samples.by_name("eval-loader")).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            api_rep = json.loads(resp.read())
        check("api health ok", health.get("status") == "ok")
        check("api detonate HOLD + invariants",
              api_rep["verdict"] == "HOLD" and api_rep["invariants"]["executed"] is False)
    finally:
        server.shutdown()
    return out


def main(argv: list[str]) -> int:
    args = argv[1:]
    cmd = args[0] if args else "checks"
    if cmd == "checks":
        results = checks()
        failed = 0
        for name, ok, detail in results:
            print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}")
            failed += 0 if ok else 1
        print(f"CHECKS: {len(results) - failed}/{len(results)} passed")
        return 1 if failed else 0
    if cmd == "demo":
        for sample in samples.SAMPLES:
            rep = report.build_report(sample)
            print(f"{sample['name']:18s} {rep['verdict']:5s} "
                  f"threat {rep['threat']['score']:3d} ({rep['threat']['band']})")
        return 0
    if cmd == "triage":
        print(json.dumps(chamber.triage(samples.by_name(args[1])), indent=2))
        return 0
    if cmd == "detonate":
        print(report.render_markdown(report.build_report(samples.by_name(args[1]))))
        return 0
    if cmd == "serve":
        from sandboxapi import server as srv
        port = int(args[1]) if len(args) > 1 else 8771
        server = srv.serve(port)
        print(f"sandbox-api listening on http://127.0.0.1:{port} (Ctrl+C to stop)")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        return 0
    if cmd == "hold-demo":
        verdict = council.decide("execute_payload")
        print(f"{verdict['verdict']}: {verdict['action']} - {verdict['reason']}")
        return 2
    print(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
