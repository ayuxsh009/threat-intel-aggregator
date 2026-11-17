"""Tests for the v2.1 features: extra sources, threat score, local intel,
verdicts, text extraction, exports and the infrastructure graph."""

import json
from datetime import datetime, timezone
from unittest import mock

import pytest

from tia import export, extract, graph, intel, scanner, sources, threatscore

from conftest import REAL_QUERY_RDAP


def VT(m, s=0, total=70, **extra):
    return {"ok": True, "found": True, "malicious": m, "suspicious": s, "harmless": 0, "undetected": 0,
            "total": total, "detections": [], "tags": [], **extra}


def AB(c, reports=10, whitelisted=False, **extra):
    return {"ok": True, "confidence": c, "reports": reports, "whitelisted": whitelisted, **extra}


TF_HIT = {"ok": True, "found": True, "families": ["Cobalt Strike"], "threat_types": ["botnet_cc"], "confidence": 90}
UH_ONLINE = {"ok": True, "found": True, "count": 4, "online": 2, "threats": ["malware_download"], "tags": []}

# ---------------------------------------------------------------- sources


def test_threatfox_parses_and_filters_ip_port(fake_response):
    payload = {"query_status": "ok", "data": [
        {"ioc": "203.0.113.5:443", "malware_printable": "Cobalt Strike", "threat_type": "botnet_cc",
         "threat_type_desc": "Botnet C&C", "confidence_level": 75, "first_seen": "2026-10-01 10:00:00 UTC"},
        {"ioc": "203.0.113.50:80", "malware_printable": "Other", "threat_type": "payload", "confidence_level": 100},
    ]}
    with mock.patch("requests.post", return_value=fake_response(200, payload)) as post:
        r = sources.query_threatfox("203.0.113.5", "IP", "KEY")
    assert post.call_args.kwargs["headers"] == {"Auth-Key": "KEY"}
    assert r["found"] and r["families"] == ["Cobalt Strike"] and r["confidence"] == 75
    assert len(r["matches"]) == 1  # 203.0.113.50 is not a match for 203.0.113.5


def test_threatfox_no_result_and_missing_key(fake_response):
    assert sources.query_threatfox("x.com", "Domain", "")["skipped"]
    with mock.patch("requests.post", return_value=fake_response(200, {"query_status": "no_result", "data": "none"})):
        r = sources.query_threatfox("x.com", "Domain", "KEY")
    assert r["ok"] and not r["found"]
    with mock.patch("requests.post", return_value=fake_response(200, {"query_status": "unknown_auth_key"})):
        assert not sources.query_threatfox("x.com", "Domain", "BAD")["ok"]


def test_urlhaus_host_and_url(fake_response):
    host = {"query_status": "ok", "url_count": "3", "firstseen": "2026-09-01", "urlhaus_reference": "https://u/h",
            "urls": [{"url_status": "online", "threat": "malware_download", "tags": ["exe"]},
                     {"url_status": "offline", "threat": "malware_download", "tags": ["elf"]}]}
    with mock.patch("requests.post", return_value=fake_response(200, host)) as post:
        r = sources.query_urlhaus("bad.example", "Domain", "KEY")
    assert post.call_args.args[0].endswith("/host/")
    assert r["found"] and r["count"] == 3 and r["online"] == 1 and r["tags"] == ["elf", "exe"]
    with mock.patch("requests.post", return_value=fake_response(200, {"query_status": "no_results"})):
        assert not sources.query_urlhaus("http://a.example/x", "URL", "KEY")["found"]
    assert sources.query_urlhaus("a" * 40, "SHA1", "KEY")["note"]


def test_rdap_age_and_registrar(fake_response):
    payload = {
        "events": [{"eventAction": "registration", "eventDate": "2026-11-07T00:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2027-11-07T00:00:00Z"}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                       ["fn", {}, "text", "Example Registrar"]]]}],
        "status": ["active"],
    }
    now = datetime(2026, 11, 17, tzinfo=timezone.utc)
    with mock.patch("requests.get", return_value=fake_response(200, payload)) as get:
        r = REAL_QUERY_RDAP("login.portal.evil.co.uk", now=now)
    assert get.call_args.args[0].endswith("/evil.co.uk")
    assert r["age_days"] == 10 and r["registrar"] == "Example Registrar" and r["expires"] == "2027-11-07"
    with mock.patch("requests.get", return_value=fake_response(404, {})):
        assert REAL_QUERY_RDAP("nothing.example")["found"] is False


def test_registrable_domain():
    assert sources.registrable_domain("a.b.example.com") == "example.com"
    assert sources.registrable_domain("x.example.co.uk") == "example.co.uk"

# ---------------------------------------------------------------- threat score


def test_factors_are_explained_and_capped():
    f = threatscore.compute_factors("IP", VT(30, s=10), AB(100, reports=500),
                                    {"ok": True, "found": True, "ports": [22, 445, 3389], "vulns": ["CVE-1", "CVE-2"]},
                                    TF_HIT, UH_ONLINE)
    labels = " | ".join(x["label"] for x in f)
    assert "SMB (445)" in labels and "RDP (3389)" in labels and "Cobalt Strike" in labels
    vt_points = next(x["points"] for x in f if x["source"] == "VirusTotal" and "malicious" in x["label"])
    assert vt_points == 45  # capped
    assert threatscore.assess("IP", VT(30, s=10), AB(100, reports=500), None, TF_HIT, UH_ONLINE)["score"] == 100


def test_score_escalates_but_never_downgrades():
    # VT 9 (Medium) + AbuseIPDB 75 (Medium) + volume: combined evidence crosses the High band.
    a = threatscore.assess("IP", VT(9), AB(75, reports=200))
    assert a["rule_risk"] == "Medium" and a["risk"] == "High" and a["score"] >= 70
    assert any("raised severity" in r for r in a["reasons"])
    # VT 10 is High by rule even though the score alone (45) is only Medium.
    b = threatscore.assess("Domain", VT(10))
    assert b["score"] == 45 and b["risk"] == "High"


def test_exposure_and_young_domain_lift_clean_results():
    exposed = threatscore.assess("IP", VT(0), AB(0), {"ok": True, "found": True, "ports": [23, 445, 3389],
                                                      "vulns": ["CVE-1", "CVE-2", "CVE-3"]})
    assert exposed["risk"] == "Low" and exposed["score"] == 24
    young = threatscore.assess("Domain", VT(0), rdap={"ok": True, "found": True, "age_days": 3})
    assert young["score"] == 15 and young["risk"] == "Low"


def test_unknown_stays_unknown_and_whitelist_lowers():
    assert threatscore.assess("Domain", None, rdap={"ok": True, "found": True, "age_days": 1})["risk"] == "Unknown"
    w = threatscore.assess("IP", VT(0), AB(0, whitelisted=True))
    assert w["score"] == 0 and w["risk"] == "Legitimate"


def test_feed_hits_set_rule_level():
    assert threatscore.assess("Domain", VT(0), threatfox=TF_HIT)["rule_risk"] == "High"
    old = {"ok": True, "found": True, "count": 2, "online": 0, "threats": []}
    assert threatscore.assess("Domain", VT(0), urlhaus=old)["rule_risk"] == "Medium"
    # Not being listed is not evidence of safety.
    assert threatscore.assess("Domain", None, threatfox={"ok": True, "found": False})["risk"] == "Unknown"


def test_analyst_verdict_overrides():
    m = threatscore.assess("Domain", VT(0), verdict={"verdict": "malicious", "username": "dana", "note": "phish kit"})
    assert m["risk"] == "High" and m["reasons"][0].startswith("Analyst verdict: confirmed malicious by dana")
    b = threatscore.assess("IP", VT(25), verdict={"verdict": "benign", "username": "dana"})
    assert b["risk"] == "Legitimate" and b["rule_risk"] == "High"

# ---------------------------------------------------------------- local intel


def test_sightings_and_diff():
    hist = [
        {"session_id": "s2", "label": "b", "created_at": "2026-11-10T09:00:00",
         "result": {"timestamp": "2026-11-10T09:00:00", "risk": "Low", "score": 10}},
        {"session_id": "s1", "label": "a", "created_at": "2026-11-01T09:00:00",
         "result": {"timestamp": "2026-11-01T09:00:00", "risk": "High", "score": 80}},
    ]
    s = intel.sightings(hist)
    assert s["count"] == 2 and s["investigations"] == 2 and s["worst_risk"] == "High"
    assert s["first_seen"].startswith("2026-11-01") and s["last_risk"] == "Low"
    assert intel.sightings([]) == {"count": 0}

    prev = {"risk": "Low", "score": 10, "vt": VT(2), "shodan": {"ok": True, "ports": [80], "vulns": []},
            "threatfox": {"ok": True, "found": False}}
    cur = {"risk": "Medium", "score": 45, "vt": VT(9), "shodan": {"ok": True, "ports": [80, 3389], "vulns": ["CVE-9"]},
           "threatfox": {"ok": True, "found": True}}
    changes = intel.diff(prev, cur)
    assert "Severity Low → Medium" in changes and "VirusTotal detections 2 → 9" in changes
    assert "Newly open ports: 3389" in changes and "New CVEs: CVE-9" in changes and "Now listed in ThreatFox" in changes
    assert intel.diff(None, cur) == []


def test_store_history_and_verdicts(store):
    sid = store.create_session("dana", "single", "first")
    store.add_scan(sid, "dana", {"ioc": "evil.example", "type": "Domain", "risk": "High", "timestamp": "2026-11-01T00:00:00"})
    sid2 = store.create_session("lee", "single", "second")
    store.add_scan(sid2, "lee", {"ioc": "evil.example", "type": "Domain", "risk": "Low", "timestamp": "2026-11-02T00:00:00"})
    hist = store.ioc_history("evil.example")
    assert [h["label"] for h in hist] == ["second", "first"]  # newest first, across users

    store.set_verdict("evil.example", "benign", ioc_type="Domain", note="internal", username="dana")
    store.set_verdict("evil.example", "malicious", ioc_type="Domain", note="confirmed", username="lee")
    v = store.get_verdict("evil.example")
    assert v["verdict"] == "malicious" and v["username"] == "lee"
    assert len(store.list_verdicts("malicious")) == 1 and store.list_verdicts("benign") == []
    with pytest.raises(ValueError):
        store.set_verdict("x", "maybe")
    store.delete_verdict("evil.example")
    assert store.get_verdict("evil.example") is None


def test_scan_uses_history_verdict_and_reports_changes(store):
    keys = {"vt": "k"}
    with mock.patch.object(sources, "query_virustotal", return_value=VT(2)):
        first = scanner.scan_ioc("evil.example", keys, store=store)
    sid = store.create_session("dana", "single", "x")
    store.add_scan(sid, "dana", first)
    assert first["sightings"] == {"count": 0} and first["changes"] == []

    with mock.patch.object(sources, "query_virustotal", return_value=VT(12)):
        second = scanner.scan_ioc("evil.example", keys, store=store)
    assert second["sightings"]["count"] == 1
    assert "VirusTotal detections 2 → 12" in second["changes"] and second["risk"] == "High"

    store.set_verdict("evil.example", "benign", username="dana")
    with mock.patch.object(sources, "query_virustotal", return_value=VT(12)):
        third = scanner.scan_ioc("evil.example", keys, store=store)
    assert third["risk"] == "Legitimate" and third["verdict"]["verdict"] == "benign"


def test_scan_queries_abusech_and_rdap_for_urls():
    with mock.patch.object(sources, "query_virustotal", return_value=VT(0)), \
         mock.patch.object(sources, "query_threatfox", return_value=TF_HIT) as tf, \
         mock.patch.object(sources, "query_urlhaus", return_value={"ok": True, "found": False}) as uh, \
         mock.patch.object(sources, "query_rdap", return_value={"ok": True, "found": True, "age_days": 2}) as rd:
        r = scanner.scan_ioc("hxxps://login.evil[.]example/x", {"vt": "k", "abusech": "a"})
    assert tf.called and uh.called and rd.call_args.args[0] == "login.evil.example"
    assert r["risk"] == "High" and r["score"] >= 55 and r["rdap"]["age_days"] == 2


def test_scan_skips_abusech_without_key():
    with mock.patch.object(sources, "query_virustotal", return_value=VT(0)), \
         mock.patch.object(sources, "query_threatfox") as tf:
        r = scanner.scan_ioc("8.8.8.8", {"vt": "k"}, use_shodan=False)
    assert not tf.called and r["threatfox"] is None and r["rdap"] is None

# ---------------------------------------------------------------- extraction


def test_extract_from_messy_text():
    text = """
    Subject: Invoice overdue
    Payload: hxxps://cdn-update[.]top/files/a.exe (mirror at http://203.0.113.77:8080/b).
    Beacon to 185.220.101[.]8 and evil-domain(.)com every 60s; internal host 10.0.0.5.
    Dropped invoice.pdf and run.ps1. SHA256 9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08
    Version 1.2.3.4.5 is not an IP. Contact soc@corp-mail.net. Schema: http://schemas.microsoft.com/x
    """
    found = extract.extract(text)
    values = [f["ioc"] for f in found]
    assert "https://cdn-update.top/files/a.exe" in values
    assert "http://203.0.113.77:8080/b" in values
    assert "185.220.101.8" in values and "evil-domain.com" in values and "corp-mail.net" in values
    assert "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" in values
    assert "10.0.0.5" not in values and "invoice.pdf" not in values and "run.ps1" not in values
    assert "cdn-update.top" not in values  # host already covered by its URL
    assert not any(v.startswith("1.2.3.4") for v in values)
    assert not any("schemas.microsoft.com" in v for v in values)
    types = {f["ioc"]: f["type"] for f in found}
    assert types["185.220.101.8"] == "IP" and types["evil-domain.com"] == "Domain"
    assert "10.0.0.5" in [f["ioc"] for f in extract.extract(text, include_private=True)]


def test_extract_dedupes_and_handles_empty():
    assert extract.extract("") == []
    assert len(extract.extract("evil.com EVIL.com evil[.]com")) == 1

# ---------------------------------------------------------------- exports


RESULTS = [
    {"ioc": "203.0.113.5", "type": "IP", "risk": "High", "score": 88, "timestamp": "2026-11-17T10:00:00",
     "reasons": ["VirusTotal: 12 of 70"], "threatfox": TF_HIT},
    {"ioc": "bad.example", "type": "Domain", "risk": "Medium", "score": 50, "timestamp": "2026-11-17T10:01:00"},
    {"ioc": "http://bad.example/it's", "type": "URL", "risk": "Low", "score": 20},
    {"ioc": "44d88612fea8a8f36de82e1278abb02f", "type": "MD5", "risk": "High", "score": 90},
    {"ioc": "ok.example", "type": "Domain", "risk": "Legitimate", "score": 0},
]


def test_stix_bundle():
    bundle = json.loads(export.stix_bundle(RESULTS, author="dana"))
    assert bundle["type"] == "bundle"
    inds = [o for o in bundle["objects"] if o["type"] == "indicator"]
    patterns = {o["pattern"] for o in inds}
    assert "[ipv4-addr:value = '203.0.113.5']" in patterns
    assert "[file:hashes.'MD5' = '44d88612fea8a8f36de82e1278abb02f']" in patterns
    assert "[url:value = 'http://bad.example/it\\'s']" in patterns
    assert not any("ok.example" in p for p in patterns)
    ip = next(o for o in inds if "203.0.113.5" in o["pattern"])
    assert ip["confidence"] == 88 and "cobalt strike" in ip["labels"] and ip["spec_version"] == "2.1"
    assert all(o["created_by_ref"].startswith("identity--") for o in inds)
    only_high = json.loads(export.stix_bundle(RESULTS, risks=("High",)))
    assert len([o for o in only_high["objects"] if o["type"] == "indicator"]) == 2


def test_blocklist():
    text = export.blocklist(RESULTS, title="Case 42")
    assert text.startswith("# Case 42")
    assert "203.0.113.5" in text and "bad.example" in text and "44d88612fea8a8f36de82e1278abb02f" in text
    assert "ok.example" not in text and "http://bad.example" not in text  # Low excluded by default

# ---------------------------------------------------------------- graph


def _res(ioc, risk="High", org=None, family=None, kind="IP"):
    r = {"ioc": ioc, "type": kind, "risk": risk, "score": 50}
    if org:
        r["shodan"] = {"ok": True, "found": True, "org": org, "hostnames": [], "ports": []}
    if family:
        r["threatfox"] = {"ok": True, "found": True, "families": [family]}
    return r


def test_graph_clusters_shared_attributes():
    results = [
        _res("203.0.113.1", org="Bad Hosting", family="Emotet"),
        _res("203.0.113.2", org="Bad Hosting"),
        _res("203.0.113.3", risk="Low", family="Emotet"),
        _res("198.51.100.9", org="Lonely Org"),
        _res("http://203.0.113.1/x", kind="URL"),
    ]
    g = graph.build(results)
    labels = {c["label"]: c for c in g["clusters"]}
    assert set(labels) == {"Bad Hosting", "Emotet"}  # Lonely Org links nothing
    assert labels["Emotet"]["worst"] == "High" and len(labels["Bad Hosting"]["members"]) == 2
    assert ("http://203.0.113.1/x", "203.0.113.1") in g["edges"]  # URL host linked directly
    assert "198.51.100.9" not in [r["ioc"] for r in g["iocs"]]
    only_org = graph.build(results, link_types=("org",))
    assert [c["label"] for c in only_org["clusters"]] == ["Bad Hosting"]
    fig = graph.figure(g)
    assert len(fig.data) >= 3


def test_graph_layout_is_deterministic_and_handles_tiny_inputs():
    assert graph.layout([], []) == {}
    assert graph.layout(["a"], []) == {"a": (0.0, 0.0)}
    p1 = graph.layout(["a", "b", "c"], [("a", "b")])
    assert p1 == graph.layout(["a", "b", "c"], [("a", "b")])


def test_latest_per_ioc():
    rows = [{"ioc": "a", "risk": "Low"}, {"ioc": "a", "risk": "High"}]
    assert graph.latest_per_ioc(rows) == [{"ioc": "a", "risk": "High"}]
