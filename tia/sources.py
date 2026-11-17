"""Clients for VirusTotal, AbuseIPDB, Shodan, abuse.ch (ThreatFox, URLhaus) and RDAP.

Every function returns a plain dict with ``ok`` (bool). On failure it carries
``error``; when the API key is missing it carries ``skipped: True``. Nothing
here raises, so one failing source never breaks a scan.
"""

from __future__ import annotations

import time

import requests

VT_SEARCH_URL = "https://www.virustotal.com/api/v3/search"
VT_GUI_URL = "https://www.virustotal.com/gui"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
TIMEOUT = 15
MAX_RETRIES = 2

_VT_GUI_PATHS = {"ip_address": "ip-address", "domain": "domain", "file": "file", "url": "url"}


def _skipped(name: str) -> dict:
    return {"ok": False, "skipped": True, "error": f"No {name} API key configured."}


def _retry_after(resp, attempt: int) -> float:
    try:
        return min(float(resp.headers.get("Retry-After", "")), 60.0)
    except (TypeError, ValueError):
        return 15.0 * (attempt + 1)


def _get(url: str, *, headers: dict, params: dict, sleep=time.sleep):
    """GET with a short retry when the API answers 429 (rate limited)."""
    resp = None
    for attempt in range(MAX_RETRIES + 1):
        resp = requests.get(url, headers=headers, params=params, timeout=TIMEOUT)
        if resp.status_code != 429 or attempt == MAX_RETRIES:
            return resp
        sleep(_retry_after(resp, attempt))
    return resp


def _http_error(name: str, resp) -> dict:
    if resp.status_code == 429:
        msg = f"{name} rate limit reached (HTTP 429). Wait a minute or use a higher-tier key."
    elif resp.status_code in (401, 403):
        msg = f"{name} rejected the API key (HTTP {resp.status_code})."
    else:
        msg = f"{name} returned HTTP {resp.status_code}: {resp.text[:200]}"
    return {"ok": False, "error": msg, "status": resp.status_code}


def query_virustotal(ioc: str, api_key: str, *, sleep=time.sleep) -> dict:
    if not api_key:
        return _skipped("VirusTotal")
    try:
        resp = _get(VT_SEARCH_URL, headers={"x-apikey": api_key}, params={"query": ioc}, sleep=sleep)
    except requests.RequestException as exc:
        return {"ok": False, "error": f"VirusTotal network error: {exc}"}
    if resp.status_code != 200:
        return _http_error("VirusTotal", resp)
    try:
        items = resp.json().get("data") or []
    except ValueError:
        return {"ok": False, "error": "VirusTotal returned invalid JSON."}

    if not items:
        return {"ok": True, "found": False, "malicious": 0, "suspicious": 0,
                "harmless": 0, "undetected": 0, "total": 0, "detections": []}

    item = items[0]
    attrs = item.get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    detections = sorted(
        (
            {"engine": engine, "category": r.get("category"), "result": r.get("result")}
            for engine, r in results.items()
            if r.get("category") in ("malicious", "suspicious")
        ),
        key=lambda d: (d["category"] != "malicious", d["engine"].lower()),
    )
    gui = _VT_GUI_PATHS.get(item.get("type"))
    return {
        "ok": True,
        "found": True,
        "malicious": int(stats.get("malicious", 0) or 0),
        "suspicious": int(stats.get("suspicious", 0) or 0),
        "harmless": int(stats.get("harmless", 0) or 0),
        "undetected": int(stats.get("undetected", 0) or 0),
        "total": int(sum(v for v in stats.values() if isinstance(v, (int, float)))),
        "reputation": attrs.get("reputation"),
        "tags": attrs.get("tags", []) or [],
        "detections": detections,
        "link": f"{VT_GUI_URL}/{gui}/{item.get('id')}" if gui and item.get("id") else None,
    }


def query_abuseipdb(ip: str, api_key: str, *, max_age_days: int = 90, sleep=time.sleep) -> dict:
    if not api_key:
        return _skipped("AbuseIPDB")
    try:
        resp = _get(
            ABUSEIPDB_URL,
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": max_age_days},
            sleep=sleep,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": f"AbuseIPDB network error: {exc}"}
    if resp.status_code != 200:
        return _http_error("AbuseIPDB", resp)
    try:
        d = resp.json().get("data") or {}
    except ValueError:
        return {"ok": False, "error": "AbuseIPDB returned invalid JSON."}
    return {
        "ok": True,
        "confidence": int(d.get("abuseConfidenceScore") or 0),
        "reports": int(d.get("totalReports") or 0),
        "distinct_users": d.get("numDistinctUsers"),
        "whitelisted": bool(d.get("isWhitelisted")),
        "country": d.get("countryCode"),
        "isp": d.get("isp"),
        "domain": d.get("domain"),
        "usage": d.get("usageType"),
        "last_reported": d.get("lastReportedAt"),
        "link": f"https://www.abuseipdb.com/check/{ip}",
    }


def query_shodan(ip: str, api_key: str) -> dict:
    if not api_key:
        return _skipped("Shodan")
    try:
        import shodan
    except ImportError:
        return {"ok": False, "error": "The 'shodan' package is not installed."}
    try:
        host = shodan.Shodan(api_key).host(ip)
    except shodan.APIError as exc:
        msg = str(exc)
        if "No information available" in msg:
            return {"ok": True, "found": False, "ports": [], "vulns": [], "hostnames": []}
        return {"ok": False, "error": f"Shodan: {msg}"}
    except Exception as exc:  # network errors etc.
        return {"ok": False, "error": f"Shodan error: {exc}"}
    return {
        "ok": True,
        "found": True,
        "ports": sorted(host.get("ports", []) or []),
        "org": host.get("org"),
        "isp": host.get("isp"),
        "os": host.get("os"),
        "country": host.get("country_name"),
        "hostnames": host.get("hostnames", []) or [],
        "vulns": sorted(host.get("vulns", []) or []),
        "last_update": host.get("last_update"),
        "link": f"https://www.shodan.io/host/{ip}",
    }


# -- abuse.ch (ThreatFox, URLhaus) ------------------------------------------
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1"
RDAP_URL = "https://rdap.org/domain"
HASH_KINDS = ("MD5", "SHA1", "SHA256")


def _post(url: str, *, headers: dict, sleep=time.sleep, **kwargs):
    resp = None
    for attempt in range(MAX_RETRIES + 1):
        resp = requests.post(url, headers=headers, timeout=TIMEOUT, **kwargs)
        if resp.status_code != 429 or attempt == MAX_RETRIES:
            return resp
        sleep(_retry_after(resp, attempt))
    return resp


def _threatfox_matches(ioc: str, kind: str, rows: list) -> list:
    """ThreatFox stores IPs as ip:port and matches by substring; keep real matches only."""
    ioc_l = ioc.lower()
    out = []
    for row in rows:
        value = str(row.get("ioc", "")).lower()
        if kind == "IP":
            ok = value == ioc_l or value.startswith(ioc_l + ":")
        elif kind == "Domain":
            ok = value == ioc_l or value.endswith("." + ioc_l)
        else:
            ok = value == ioc_l
        if ok:
            out.append(row)
    return out


def query_threatfox(ioc: str, kind: str, api_key: str, *, sleep=time.sleep) -> dict:
    """Known malware infrastructure (C2 servers, payload hosts) and families."""
    if not api_key:
        return _skipped("abuse.ch")
    if kind in HASH_KINDS:
        body = {"query": "search_hash", "hash": ioc}
    else:
        body = {"query": "search_ioc", "search_term": ioc}
    try:
        resp = _post(THREATFOX_URL, headers={"Auth-Key": api_key}, json=body, sleep=sleep)
    except requests.RequestException as exc:
        return {"ok": False, "error": f"ThreatFox network error: {exc}"}
    if resp.status_code != 200:
        return _http_error("ThreatFox", resp)
    try:
        payload = resp.json()
    except ValueError:
        return {"ok": False, "error": "ThreatFox returned invalid JSON."}
    status = payload.get("query_status")
    if status not in ("ok", "no_result", "no_results"):
        return {"ok": False, "error": f"ThreatFox: {status}"}
    rows = payload.get("data") if isinstance(payload.get("data"), list) else []
    matches = rows if kind in HASH_KINDS else _threatfox_matches(ioc, kind, rows)
    if not matches:
        return {"ok": True, "found": False, "matches": []}
    return {
        "ok": True,
        "found": True,
        "families": sorted({m.get("malware_printable") for m in matches if m.get("malware_printable")}),
        "threat_types": sorted({m.get("threat_type_desc") or m.get("threat_type")
                                for m in matches if m.get("threat_type")}),
        "confidence": max(int(m.get("confidence_level") or 0) for m in matches),
        "first_seen": min((m.get("first_seen") or "") for m in matches) or None,
        "last_seen": max((m.get("last_seen") or m.get("first_seen") or "") for m in matches) or None,
        "tags": sorted({t for m in matches for t in (m.get("tags") or [])})[:10],
        "matches": [{"ioc": m.get("ioc"), "malware": m.get("malware_printable"), "type": m.get("threat_type"),
                     "confidence": m.get("confidence_level"), "first_seen": m.get("first_seen")}
                    for m in matches[:20]],
        "link": f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}",
    }


def query_urlhaus(ioc: str, kind: str, api_key: str, *, sleep=time.sleep) -> dict:
    """Malware distribution URLs, hosts and payloads."""
    if not api_key:
        return _skipped("abuse.ch")
    if kind in ("IP", "Domain"):
        endpoint, data = "host", {"host": ioc}
    elif kind == "URL":
        endpoint, data = "url", {"url": ioc}
    elif kind == "MD5":
        endpoint, data = "payload", {"md5_hash": ioc}
    elif kind == "SHA256":
        endpoint, data = "payload", {"sha256_hash": ioc}
    else:
        return {"ok": True, "found": False, "note": f"URLhaus does not index {kind}."}
    try:
        resp = _post(f"{URLHAUS_URL}/{endpoint}/", headers={"Auth-Key": api_key}, data=data, sleep=sleep)
    except requests.RequestException as exc:
        return {"ok": False, "error": f"URLhaus network error: {exc}"}
    if resp.status_code != 200:
        return _http_error("URLhaus", resp)
    try:
        d = resp.json()
    except ValueError:
        return {"ok": False, "error": "URLhaus returned invalid JSON."}
    status = d.get("query_status")
    if status in ("no_results", "no_result"):
        return {"ok": True, "found": False}
    if status != "ok":
        return {"ok": False, "error": f"URLhaus: {status}"}

    if endpoint == "host":
        urls = d.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        threats = sorted({u.get("threat") for u in urls if u.get("threat")})
        tags = sorted({t for u in urls for t in (u.get("tags") or [])})
        count = int(d.get("url_count") or len(urls))
        first_seen = d.get("firstseen")
    elif endpoint == "url":
        online = 1 if d.get("url_status") == "online" else 0
        threats = [d["threat"]] if d.get("threat") else []
        tags = d.get("tags") or []
        count = 1
        first_seen = d.get("date_added")
    else:
        online = 0
        threats = [d["signature"]] if d.get("signature") else []
        tags = [d["file_type"]] if d.get("file_type") else []
        count = int(d.get("url_count") or 0)
        first_seen = d.get("firstseen")
    return {
        "ok": True,
        "found": True,
        "count": count,
        "online": online,
        "threats": threats,
        "tags": list(tags)[:10],
        "first_seen": first_seen,
        "link": d.get("urlhaus_reference"),
    }


# -- RDAP (domain registration, no key needed) ------------------------------
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "go"}


def registrable_domain(host: str) -> str:
    """Best-effort registrable domain (example.co.uk, evil.com) without a suffix list."""
    parts = host.lower().rstrip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _vcard_name(entity: dict):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
            return item[3]
    return None


def query_rdap(domain: str, *, now=None) -> dict:
    """Registration date, age, registrar and expiry for a domain."""
    from datetime import datetime, timezone

    name = registrable_domain(domain)
    try:
        resp = requests.get(f"{RDAP_URL}/{name}", headers={"Accept": "application/rdap+json"}, timeout=TIMEOUT)
    except requests.RequestException as exc:
        return {"ok": False, "error": f"RDAP network error: {exc}"}
    if resp.status_code == 404:
        return {"ok": True, "found": False, "domain": name}
    if resp.status_code != 200:
        return _http_error("RDAP", resp)
    try:
        d = resp.json()
    except ValueError:
        return {"ok": False, "error": "RDAP returned invalid JSON."}

    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", []) if isinstance(e, dict)}
    registered = events.get("registration")
    age_days = None
    if registered:
        try:
            when = datetime.fromisoformat(registered.replace("Z", "+00:00"))
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            age_days = max(0, ((now or datetime.now(timezone.utc)) - when).days)
        except ValueError:
            pass
    registrar = next((_vcard_name(e) for e in d.get("entities", []) if "registrar" in (e.get("roles") or [])), None)
    return {
        "ok": True,
        "found": True,
        "domain": name,
        "registered": (registered or "")[:10] or None,
        "age_days": age_days,
        "expires": (events.get("expiration") or "")[:10] or None,
        "registrar": registrar,
        "status": d.get("status") or [],
        "link": f"https://client.rdap.org/?type=domain&object={name}",
    }
