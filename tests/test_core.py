import json
from unittest import mock

import pytest

from tia import auth, ioc, legacy, report, scanner, scoring, sources

# ---------------------------------------------------------------- IOC parsing

@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", "IP"),
    ("2001:4860:4860::8888", "IP"),
    ("example.com", "Domain"),
    ("sub.example.co.uk", "Domain"),
    ("https://evil.com/x?a=1&b=2", "URL"),
    ("d41d8cd98f00b204e9800998ecf8427e", "MD5"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "SHA1"),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "SHA256"),
    ("999.999.999.999", "Unknown"),   # v1 accepted this as an IP
    ("abcd:ef", "Unknown"),           # v1 accepted this as an IP
    ("hello world", "Unknown"),
    ("", "Unknown"),
])
def test_classify(value, expected):
    assert ioc.classify(value) == expected


@pytest.mark.parametrize("raw,expected", [
    ("evil[.]com", ("evil.com", "Domain")),
    ("EVIL(.)COM", ("evil.com", "Domain")),
    ("evil[dot]com", ("evil.com", "Domain")),
    ("hxxp://bad[.]site/path", ("http://bad.site/path", "URL")),
    ("hxxps[:]//bad[.]site", ("https://bad.site", "URL")),
    ("1.2.3[.]4", ("1.2.3.4", "IP")),
    ("  D41D8CD98F00B204E9800998ECF8427E ", ("d41d8cd98f00b204e9800998ecf8427e", "MD5")),
])
def test_refang_and_normalize(raw, expected):
    assert ioc.normalize(raw) == expected


def test_parse_list_dedupes_and_refangs():
    text = "8.8.8.8, evil[.]com\nevil.com;8.8.8.8  https://x.org"
    assert ioc.parse_list(text) == ["8.8.8.8", "evil.com", "https://x.org"]


def test_public_ip():
    assert ioc.is_public_ip("8.8.8.8")
    assert not ioc.is_public_ip("10.0.0.1")
    assert not ioc.is_public_ip("127.0.0.1")

# ---------------------------------------------------------------- scoring

VT = lambda m, total=70: {"ok": True, "found": True, "malicious": m, "suspicious": 0, "total": total}
AB = lambda c, n=5, wl=False: {"ok": True, "confidence": c, "reports": n, "whitelisted": wl}


@pytest.mark.parametrize("vt,abuse,kind,expected", [
    (VT(0), None, "Domain", "Legitimate"),
    (VT(2), None, "URL", "Low"),
    (VT(5), None, "SHA256", "Medium"),
    (VT(12), None, "Domain", "High"),
    (VT(0), AB(0), "IP", "Legitimate"),
    (VT(0), AB(85), "IP", "High"),
    (VT(0), AB(40), "IP", "Medium"),
    (VT(0), AB(10), "IP", "Low"),
    (VT(40), AB(0), "IP", "High"),             # fix: VT is no longer overridden by AbuseIPDB=0
    (VT(0), AB(0, n=500), "IP", "Legitimate"), # fix: report count alone no longer drives risk
    (VT(12), AB(100, wl=True), "IP", "High"),  # whitelist cancels AbuseIPDB only
    (VT(0), AB(100, wl=True), "IP", "Legitimate"),
])
def test_score(vt, abuse, kind, expected):
    assert scoring.score(kind, vt, abuse)[0] == expected


def test_score_unknown_when_no_source_answers():
    failed = {"ok": False, "error": "HTTP 429"}
    assert scoring.score("Domain", failed, None)[0] == "Unknown"
    assert scoring.score("IP", {"ok": False, "skipped": True}, {"ok": False, "skipped": True})[0] == "Unknown"
    # AbuseIPDB alone is enough for an IP
    assert scoring.score("IP", failed, AB(90))[0] == "High"

# ---------------------------------------------------------------- sources

VT_PAYLOAD = {"data": [{"type": "domain", "id": "evil.com", "attributes": {
    "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 50, "undetected": 12},
    "last_analysis_results": {"EngineB": {"category": "malicious", "result": "phishing"},
                              "EngineA": {"category": "suspicious", "result": "sus"},
                              "EngineC": {"category": "harmless", "result": "clean"}},
    "reputation": -20, "tags": ["phishing"]}}]}


def test_vt_missing_key_is_skipped():
    r = sources.query_virustotal("evil.com", "")
    assert r["ok"] is False and r["skipped"] is True


def test_vt_parses_and_encodes_query(fake_response):
    with mock.patch.object(sources.requests, "get", return_value=fake_response(200, VT_PAYLOAD)) as get:
        r = sources.query_virustotal("https://a.b/?x=1&y=2", "KEY")
    assert get.call_args.kwargs["params"] == {"query": "https://a.b/?x=1&y=2"}
    assert get.call_args.kwargs["headers"] == {"x-apikey": "KEY"}
    assert (r["malicious"], r["suspicious"], r["total"]) == (7, 1, 70)
    assert [d["engine"] for d in r["detections"]] == ["EngineB", "EngineA"]
    assert r["link"] == "https://www.virustotal.com/gui/domain/evil.com"


def test_vt_not_found(fake_response):
    with mock.patch.object(sources.requests, "get", return_value=fake_response(200, {"data": []})):
        r = sources.query_virustotal("x.com", "KEY")
    assert r["ok"] and not r["found"]


def test_vt_retries_on_429_then_succeeds(fake_response):
    responses = [fake_response(429, {}, {"Retry-After": "1"}), fake_response(200, VT_PAYLOAD)]
    sleeps = []
    with mock.patch.object(sources.requests, "get", side_effect=responses):
        r = sources.query_virustotal("evil.com", "KEY", sleep=sleeps.append)
    assert r["ok"] and sleeps == [1.0]


def test_vt_gives_up_after_retries(fake_response):
    with mock.patch.object(sources.requests, "get", return_value=fake_response(429)):
        r = sources.query_virustotal("evil.com", "KEY", sleep=lambda s: None)
    assert not r["ok"] and "429" in r["error"]


def test_vt_bad_key_and_network_error(fake_response):
    with mock.patch.object(sources.requests, "get", return_value=fake_response(401)):
        assert "rejected" in sources.query_virustotal("x.com", "K")["error"]
    with mock.patch.object(sources.requests, "get", side_effect=sources.requests.ConnectionError("down")):
        assert "network" in sources.query_virustotal("x.com", "K")["error"]


def test_abuseipdb(fake_response):
    payload = {"data": {"abuseConfidenceScore": 55, "totalReports": 9, "isWhitelisted": False, "countryCode": "NL"}}
    with mock.patch.object(sources.requests, "get", return_value=fake_response(200, payload)) as get:
        r = sources.query_abuseipdb("1.2.3.4", "KEY")
    assert get.call_args.kwargs["params"]["ipAddress"] == "1.2.3.4"
    assert (r["confidence"], r["reports"], r["country"]) == (55, 9, "NL")
    with mock.patch.object(sources.requests, "get", return_value=fake_response(500)):
        assert not sources.query_abuseipdb("1.2.3.4", "KEY")["ok"]


def test_shodan():
    import shodan as shodan_lib
    assert sources.query_shodan("1.2.3.4", "")["skipped"]
    api = mock.MagicMock()
    api.host.return_value = {"ports": [443, 22], "org": "ACME", "vulns": ["CVE-1"]}
    with mock.patch("shodan.Shodan", return_value=api):
        r = sources.query_shodan("1.2.3.4", "KEY")
    assert r["ports"] == [22, 443] and r["org"] == "ACME" and r["vulns"] == ["CVE-1"]
    api.host.side_effect = shodan_lib.APIError("No information available for that IP.")
    with mock.patch("shodan.Shodan", return_value=api):
        r = sources.query_shodan("1.2.3.4", "KEY")
    assert r["ok"] and not r["found"]

# ---------------------------------------------------------------- scanner

def test_scan_ip_uses_all_sources():
    with mock.patch.object(sources, "query_virustotal", return_value=VT(12)) as vt, \
         mock.patch.object(sources, "query_abuseipdb", return_value=AB(10)) as ab, \
         mock.patch.object(sources, "query_shodan", return_value={"ok": True, "found": True, "ports": [80]}) as sh:
        r = scanner.scan_ioc("185.220.101[.]8", {"vt": "a", "abuseipdb": "b", "shodan": "c"})
    assert r["ioc"] == "185.220.101.8" and r["type"] == "IP" and r["risk"] == "High"
    assert vt.called and ab.called and sh.called


def test_scan_private_ip_skips_lookups():
    with mock.patch.object(sources, "query_virustotal") as vt:
        r = scanner.scan_ioc("192.168.1.10", {"vt": "a"})
    assert not vt.called and r["risk"] == "Unknown" and r["notes"]


def test_scan_without_keys_is_unknown_not_legitimate():
    r = scanner.scan_ioc("evil.com", {})
    assert r["risk"] == "Unknown" and r["skipped"] and not r["errors"]


def test_scan_reports_errors():
    with mock.patch.object(sources, "query_virustotal", return_value={"ok": False, "error": "rate limit"}):
        r = scanner.scan_ioc("evil.com", {"vt": "k"})
    assert r["risk"] == "Unknown" and r["errors"] == ["VirusTotal: rate limit"]


def test_to_frame():
    df = scanner.to_frame([{"ioc": "a.com", "type": "Domain", "risk": "Low", "timestamp": "2026-01-01T10:00:00",
                            "vt": VT(2), "abuse": None, "shodan": None, "errors": []}])
    assert df.loc[0, "vt_malicious"] == 2 and df["timestamp"].notna().all()
    assert scanner.to_frame([]).empty

# ---------------------------------------------------------------- auth

def test_password_hashing():
    h = auth.hash_password("S3cret-pass")
    assert h.startswith("pbkdf2_sha256$") and "S3cret-pass" not in h
    assert auth.verify_password("S3cret-pass", h)
    assert not auth.verify_password("wrong", h)
    assert not auth.verify_password("x", "garbage")
    assert auth.hash_password("same") != auth.hash_password("same")  # salted


def test_validation():
    assert auth.validate_password("short1")
    assert auth.validate_password("onlyletters")
    assert auth.validate_password("good-pass-1") is None
    assert auth.validate_username("ab")
    assert auth.validate_username("analyst.one") is None


def test_authenticate(store):
    store.add_user("alice", auth.hash_password("alice-pass-1"), "analyst")
    assert auth.authenticate(store, "alice", "alice-pass-1")["role"] == "analyst"
    assert auth.authenticate(store, "ALICE", "alice-pass-1")  # case-insensitive username
    assert auth.authenticate(store, "alice", "nope") is None
    assert auth.authenticate(store, "ghost", "whatever") is None
    secret = [{"username": "dana", "password_hash": auth.hash_password("dana-pass-1")},
              {"username": "old", "password": "plain-pass-1", "role": "analyst"}]
    assert auth.authenticate(store, "dana", "dana-pass-1", secret)["role"] == "admin"
    legacy_user = auth.authenticate(store, "old", "plain-pass-1", secret)
    assert legacy_user["insecure"] and legacy_user["role"] == "analyst"

# ---------------------------------------------------------------- storage

def test_sessions_and_scoping(store):
    a = store.create_session("alice", "single", "a.com", created_at="2026-01-01T10:00:00")
    store.add_scan(a, "alice", {"ioc": "a.com", "risk": "High", "timestamp": "2026-01-01T10:00:00"})
    b = store.create_session("dana", "csv", "list.csv", created_at="2026-01-02T10:00:00")
    store.add_scans(b, "dana", [{"ioc": "b.com", "risk": "Low"}, {"ioc": "c.com", "risk": "Unknown"}])

    all_sessions = store.list_sessions()
    assert [s["id"] for s in all_sessions] == [b, a]
    assert all_sessions[0]["total"] == 2 and all_sessions[0]["unknown"] == 1
    assert [s["id"] for s in store.list_sessions("alice")] == [a]
    assert len(store.scans("dana")) == 2 and len(store.scans()) == 3

    store.delete_session(a)
    assert store.session_results(a) == []
    store.clear_history("dana")
    assert store.scans() == []


def test_users_and_settings(store):
    store.add_user("admin", "h", "admin")
    with pytest.raises(ValueError):
        store.add_user("ADMIN", "h2")
    assert store.user_count() == 1 and store.admin_count() == 1
    store.set_setting("apikey.vt", "abc")
    store.set_setting("apikey.vt", "xyz")
    assert store.get_setting("apikey.vt") == "xyz"

# ---------------------------------------------------------------- legacy import

def test_legacy_import(store, tmp_path):
    (tmp_path / "configure.json").write_text(json.dumps({"users": [{"username": "admin", "password": "admin"}]}))
    (tmp_path / "apikeys.json").write_text(json.dumps({"VT": "vtkey", "AbuseIPDB": "", "Shodan": "sh"}))
    (tmp_path / "scan_log.json").write_text(json.dumps([
        {"timestamp": "2025-07-19 15:59:43", "ioc": "185.220.101.8", "type": "IP", "risk": "Legitimate",
         "vt": {"vt_malicious": 13, "vt_data": {"malicious": 13, "harmless": 60}},
         "abuse": {"totalReports": 0, "abuseConfidenceScore": 0}, "scan_session": "s1"},
    ]))
    legacy.import_legacy_files(store, tmp_path)
    assert auth.authenticate(store, "admin", "admin")["role"] == "admin"
    assert store.get_setting("apikey.vt") == "vtkey" and store.get_setting("apikey.shodan") == "sh"
    scans = store.scans()
    assert len(scans) == 1 and scans[0]["risk"] == "High"  # re-scored with the fixed rules
    legacy.import_legacy_files(store, tmp_path)               # runs only once
    assert len(store.scans()) == 1

# ---------------------------------------------------------------- report

SAMPLE = [
    {"ioc": "185.220.101.8", "type": "IP", "risk": "High", "timestamp": "2026-01-01T10:00:00",
     "reasons": ["VirusTotal: 13 of 70 engines flag it as malicious"], "errors": [],
     "vt": VT(13), "abuse": AB(100)},
    {"ioc": "exämple.com–x中", "type": "Domain", "risk": "Unknown", "timestamp": "2026-01-01T10:01:00",
     "reasons": [], "errors": ["VirusTotal: rate limit"], "vt": {"ok": False}, "abuse": None},
]


def test_pdf_builds_with_unicode_and_many_rows():
    pdf = report.build_pdf(SAMPLE * 40, title="Weekly report — test", author="tester")
    assert pdf.startswith(b"%PDF") and len(pdf) > 2000


def test_pdf_with_chart():
    from tia import charts
    png = charts.chart_png(charts.risk_donut({"High": 1, "Unknown": 1}, print_mode=True))
    pdf = report.build_pdf(SAMPLE, title="t", author="a", chart_png=png)
    assert pdf.startswith(b"%PDF")


def test_send_email_uses_ssl_on_465():
    with mock.patch("smtplib.SMTP_SSL") as ssl:
        report.send_email(b"%PDF", "r.pdf", recipient="a@b.co", sender="c@d.co", password="p")
    ssl.return_value.__enter__.return_value.send_message.assert_called_once()

# ---------------------------------------------------------------- charts

def test_charts_build():
    from tia import charts
    df = scanner.to_frame(SAMPLE)
    for fig in (charts.risk_donut({"High": 2}), charts.risk_donut({}), charts.activity_timeline(df),
                charts.top_flagged(df), charts.type_breakdown(df)):
        assert fig.to_dict()
