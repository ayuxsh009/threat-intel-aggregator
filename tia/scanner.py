"""Scan orchestration: one indicator in, one result record out."""

from __future__ import annotations

from datetime import datetime

import pandas as pd

from urllib.parse import urlsplit

from . import intel, sources
from .ioc import classify, is_public_ip, normalize
from .threatscore import assess

SOURCE_NAMES = {"vt": "VirusTotal", "abuse": "AbuseIPDB", "shodan": "Shodan",
                "threatfox": "ThreatFox", "urlhaus": "URLhaus", "rdap": "RDAP"}
FIELDS = tuple(SOURCE_NAMES)


def _domain_for_rdap(ioc: str, kind: str) -> str | None:
    if kind == "Domain":
        return ioc
    if kind == "URL":
        host = (urlsplit(ioc).hostname or "").lower()
        if host and classify(host) == "Domain":
            return host
    return None


def scan_ioc(raw: str, keys: dict, *, use_shodan: bool = True, use_rdap: bool = True, store=None) -> dict:
    """Look up one indicator in every applicable source and score it.

    ``keys`` maps "vt", "abuseipdb", "shodan" and "abusech" to API keys (may be
    empty). With a ``store``, the scan also uses the workspace's history of the
    indicator and any analyst verdict.
    """
    ioc, kind = normalize(raw)
    notes: list[str] = []
    found = dict.fromkeys(FIELDS)

    if kind == "IP" and not is_public_ip(ioc):
        notes.append("Private or reserved address: public threat feeds hold no data for it.")
    else:
        if kind == "Unknown":
            notes.append("Unrecognised format; queried VirusTotal as free text.")
        found["vt"] = sources.query_virustotal(ioc, keys.get("vt", ""))
        if kind == "IP":
            found["abuse"] = sources.query_abuseipdb(ioc, keys.get("abuseipdb", ""))
            if use_shodan:
                found["shodan"] = sources.query_shodan(ioc, keys.get("shodan", ""))
        if kind != "Unknown" and keys.get("abusech"):
            found["threatfox"] = sources.query_threatfox(ioc, kind, keys["abusech"])
            found["urlhaus"] = sources.query_urlhaus(ioc, kind, keys["abusech"])
        domain = _domain_for_rdap(ioc, kind)
        if use_rdap and domain:
            found["rdap"] = sources.query_rdap(domain)

    history = store.ioc_history(ioc) if store is not None else []
    seen = intel.sightings(history)
    verdict = store.get_verdict(ioc) if store is not None else None
    verdict_info = {k: verdict[k] for k in ("verdict", "note", "username", "updated_at")} if verdict else None

    outcome = assess(kind, found["vt"], found["abuse"], found["shodan"], found["threatfox"],
                     found["urlhaus"], found["rdap"], seen, verdict_info)
    errors, skipped = [], []
    for field in FIELDS:
        result = found[field]
        if result and not result.get("ok"):
            (skipped if result.get("skipped") else errors).append(
                f"{SOURCE_NAMES[field]}: {result.get('error')}"
            )

    result = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "input": (raw or "").strip(),
        "ioc": ioc,
        "type": kind,
        "risk": outcome["risk"],
        "rule_risk": outcome["rule_risk"],
        "score": outcome["score"],
        "factors": outcome["factors"],
        "reasons": outcome["reasons"],
        "notes": notes,
        "errors": errors,
        "skipped": skipped,
        "verdict": verdict_info,
        "sightings": seen,
        **found,
    }
    result["changes"] = intel.diff(history[0]["result"] if history else None, result)
    return result


def summarize(result: dict) -> dict:
    """Flatten a result into one table row."""
    vt = result.get("vt") or {}
    abuse = result.get("abuse") or {}
    shodan = result.get("shodan") or {}
    return {
        "timestamp": result.get("timestamp"),
        "ioc": result.get("ioc"),
        "type": result.get("type"),
        "risk": result.get("risk", "Unknown"),
        "score": result.get("score"),
        "vt_malicious": vt.get("malicious") if vt.get("ok") else None,
        "vt_total": vt.get("total") if vt.get("ok") else None,
        "abuse_confidence": abuse.get("confidence") if abuse.get("ok") else None,
        "abuse_reports": abuse.get("reports") if abuse.get("ok") else None,
        "country": abuse.get("country") or shodan.get("country"),
        "open_ports": ", ".join(str(p) for p in shodan.get("ports", [])) if shodan.get("ok") else "",
        "issues": "; ".join(result.get("errors", [])),
    }


def to_frame(results: list[dict]) -> pd.DataFrame:
    cols = list(summarize({}).keys())
    df = pd.DataFrame([summarize(r) for r in results], columns=cols)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df
