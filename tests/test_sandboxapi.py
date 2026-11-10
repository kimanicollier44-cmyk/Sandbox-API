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


def test_fleet_chamber_verbatim():
    import hashlib
    digest = hashlib.sha256(open("sandboxapi/sandbox_api.py", "rb").read()).hexdigest()
    assert digest == "28b3365c0466027079a4985520840f6532d7d9a0c5b4239b840e561f06de54b0"


def test_fleet_chamber_run():
    from sandboxapi import payloads
    result = payloads.run_chamber()
    assert result["total"] == 7 and result["allowed"] == 4 and result["held"] == 3
    assert result["all_executed"] is False
    assert result["total_network_attempts"] == 0
