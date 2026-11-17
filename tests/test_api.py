"""Tests for the browser-extension API (normalisation, cache, queue, verdicts, auth)."""

from datetime import datetime, timedelta
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from api.lookup import LookupService, normalize_target
from api.server import create_app
from tia import keys, sources

VT_BAD = {"ok": True, "found": True, "malicious": 15, "suspicious": 0, "harmless": 50, "undetected": 5,
          "total": 70, "detections": [], "tags": []}
VT_CLEAN = dict(VT_BAD, malicious=0)
TOKEN = "test-token-123"


@pytest.fixture
def service(store):
    return LookupService(store, min_interval=0, start_worker=False,
                         secrets_loader=lambda: {"apikeys": {"VT": "k"}, "api": {"token": TOKEN}})


@pytest.fixture
def client(service):
    return TestClient(create_app(service))


def auth(token=TOKEN):
    return {"X-TI-Token": token}


@pytest.mark.parametrize("target,host", [
    ("https://www.Evil-Site.com/login?x=1", "evil-site.com"),
    ("evil-site.com", "evil-site.com"),
    ("http://sub.evil-site.com:8080/a", "sub.evil-site.com"),
    ("https://185.220.101.8/x", "185.220.101.8"),
])
def test_normalize_accepts_public_hosts(target, host):
    assert normalize_target(target) == (host, "")


@pytest.mark.parametrize("target", [
    "", "chrome://settings", "file:///C:/x.html", "http://localhost:8501", "http://192.168.1.10/",
    "http://printer", "http://nas.local", "https://intranet.corp/", "http://10.0.0.1",
])
def test_normalize_skips_local_and_browser_pages(target):
    host, reason = normalize_target(target)
    assert host is None and reason


def test_lookup_queues_then_serves_from_cache(service):
    with mock.patch.object(sources, "query_virustotal", return_value=VT_BAD) as vt:
        first = service.lookup("https://evil-site.com/a")
        assert first["status"] == "pending" and first["position"] == 1
        assert service.process_one() == "evil-site.com"
        ready = service.lookup("https://evil-site.com/b")
        again = service.lookup("evil-site.com")
    assert vt.call_count == 1  # the second and third lookups came from the database
    assert ready["status"] == "ready" and ready["cached"] and ready["result"]["risk"] == "High"
    assert ready["result"]["score"] >= 45 and again["status"] == "ready"
    sessions = service.store.list_sessions()
    assert sessions[0]["kind"] == "extension" and sessions[0]["label"].startswith("Browser extension")


def test_stale_result_is_refreshed_and_shown_meanwhile(service, store):
    sid = store.create_session("browser", "extension", "old")
    old = (datetime.now() - timedelta(days=3)).isoformat(timespec="seconds")
    store.add_scan(sid, "browser", {"ioc": "evil-site.com", "type": "Domain", "risk": "Low", "timestamp": old,
                                    "vt": dict(VT_BAD, malicious=2)})
    pending = service.lookup("evil-site.com")
    assert pending["status"] == "pending" and pending["stale"]["risk"] == "Low"
    with mock.patch.object(sources, "query_virustotal", return_value=VT_BAD):
        service.process_one()
    fresh = service.lookup("evil-site.com")
    assert fresh["result"]["risk"] == "High"
    assert "VirusTotal detections 2 → 15" in fresh["result"]["changes"]


def test_force_rescans_and_queue_positions(service):
    with mock.patch.object(sources, "query_virustotal", return_value=VT_CLEAN):
        service.lookup("one.com")
        second = service.lookup("two.com")
        assert second["position"] == 2 and service.queue_size() == 2
        service.process_one()
        service.process_one()
        assert service.lookup("one.com")["status"] == "ready"
        assert service.lookup("one.com", force=True)["status"] == "pending"


def test_current_verdict_applies_to_cached_result(service):
    with mock.patch.object(sources, "query_virustotal", return_value=VT_BAD):
        service.lookup("evil-site.com")
        service.process_one()
    res = service.set_verdict("https://evil-site.com", "benign", note="our sinkhole")
    assert res["result"]["risk"] == "Legitimate" and res["result"]["verdict"]["verdict"] == "benign"
    res = service.set_verdict("evil-site.com", None)
    assert res["result"]["risk"] == "High" and res["result"]["verdict"] is None


def test_worker_error_is_reported_once(service):
    with mock.patch("api.lookup.scan_ioc", side_effect=RuntimeError("boom")):
        service.lookup("broken.com")
        service.process_one()
    err = service.lookup("broken.com")
    assert err["status"] == "error" and "boom" in err["error"]
    assert service.lookup("broken.com")["status"] == "pending"  # retried on the next request


def test_min_interval_defaults_to_free_tier(store):
    svc = LookupService(store, start_worker=False, secrets_loader=lambda: {"apikeys": {"VT": "k"}})
    assert svc.min_interval() == 15.5
    svc = LookupService(store, start_worker=False, secrets_loader=lambda: {})
    assert svc.min_interval() == 0.0

# ---------------------------------------------------------------- HTTP


def test_health_is_open_and_lookup_needs_token(client):
    h = client.get("/api/health").json()
    assert h["ok"] and h["sources"]["VirusTotal"] and h["sources"]["RDAP"]
    assert client.get("/api/lookup", params={"target": "evil-site.com"}).status_code == 401
    assert client.get("/api/lookup", params={"target": "evil-site.com"}, headers=auth("wrong")).status_code == 401
    ok = client.get("/api/lookup", params={"target": "evil-site.com"}, headers={"Authorization": f"Bearer {TOKEN}"})
    assert ok.status_code == 200 and ok.json()["status"] == "pending"
    assert client.get("/api/auth-check", headers=auth()).json() == {"ok": True}


def test_http_lookup_skip_and_verdict(client, service):
    skipped = client.get("/api/lookup", params={"target": "http://192.168.0.1"}, headers=auth()).json()
    assert skipped["status"] == "skipped"
    with mock.patch.object(sources, "query_virustotal", return_value=VT_BAD):
        client.get("/api/lookup", params={"target": "evil-site.com"}, headers=auth())
        service.process_one()
    r = client.post("/api/verdict", json={"target": "evil-site.com", "verdict": "benign"}, headers=auth()).json()
    assert r["result"]["risk"] == "Legitimate"
    bad = client.post("/api/verdict", json={"target": "evil-site.com", "verdict": "maybe"}, headers=auth())
    assert bad.status_code == 422


def test_cors_allows_extensions_only(client):
    pre = {"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "x-ti-token"}
    ext = client.options("/api/lookup", headers={"Origin": "chrome-extension://abcdef", **pre})
    assert ext.headers.get("access-control-allow-origin") == "chrome-extension://abcdef"
    web = client.options("/api/lookup", headers={"Origin": "https://evil.example", **pre})
    assert "access-control-allow-origin" not in web.headers


def test_token_generation_and_precedence(store, monkeypatch):
    token, origin = keys.api_token(store, {})
    assert origin == "app settings" and len(token) >= 24
    assert keys.api_token(store, {})[0] == token  # stable once created
    assert keys.api_token(store, {"api": {"token": "from-secrets"}}) == ("from-secrets", "secrets")
    monkeypatch.setenv("TI_API_TOKEN", "from-env")
    assert keys.api_token(store, {"api": {"token": "x"}}) == ("from-env", "environment")
