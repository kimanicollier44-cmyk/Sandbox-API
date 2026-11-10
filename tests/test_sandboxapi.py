import json
import sys
import threading
import urllib.request

sys.path.insert(0, ".")
sys.path.insert(0, "..")

from sandboxapi import chamber, iocs, report, samples, scoring
from sandboxapi.brains import council


def test_triage_split():
    rows = [chamber.triage(s) for s in samples.SAMPLES]
    assert sum(r["verdict"] == "ALLOW" for r in rows) == 8
    assert {r["name"] for r in rows if r["verdict"] == "HOLD"} == {
        "eval-loader", "reverse-shell", "key-listener", "ransom-note"}


def test_invariants():
    rep = report.build_report(samples.by_name("hello-script"))
    assert rep["invariants"]["executed"] is False
    assert rep["invariants"]["network_calls"] == 0
    assert rep["verdict"] == "ALLOW" and rep["threat"]["score"] == 0


def test_iocs_and_scoring():
    rep = report.build_report(samples.by_name("ransom-note"))
    assert rep["iocs"].get("wallets")
    assert rep["threat"]["band"] in ("HIGH", "CRITICAL")
    row = chamber.triage(samples.by_name("app-config"))
    assert scoring.score(row, {})["score"] == 0


def test_held_not_simulated():
    rep = report.build_report(samples.by_name("eval-loader"))
    assert all(s["status"].startswith("HELD") for s in rep["detonation"].values())
    assert len(rep["council"]["seats"]) == 4


def test_council_holds():
    assert council.decide("execute_payload")["verdict"] == "HOLD"
    assert council.decide("accept_real_malware")["verdict"] == "HOLD"
    assert len(council.HOLD_ACTIONS) == 10


def test_api_roundtrip():
    from sandboxapi import server as srv
    server = srv.serve(0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/detonate",
            data=json.dumps(samples.by_name("reverse-shell")).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            rep = json.loads(resp.read())
        assert rep["verdict"] == "HOLD"
        assert "203.0.113.66" in rep["iocs"]["ips"]
    finally:
        server.shutdown()
