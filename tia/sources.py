"""Clients for VirusTotal, AbuseIPDB and Shodan.

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
