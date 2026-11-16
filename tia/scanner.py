"""Scan orchestration: one indicator in, one result record out."""

from __future__ import annotations

from datetime import datetime

import pandas as pd

from . import sources
from .ioc import is_public_ip, normalize
from .scoring import score

SOURCE_NAMES = {"vt": "VirusTotal", "abuse": "AbuseIPDB", "shodan": "Shodan"}


def scan_ioc(raw: str, keys: dict, *, use_shodan: bool = True) -> dict:
    """Look up one indicator in every applicable source and score it.

    ``keys`` maps "vt", "abuseipdb" and "shodan" to API keys (may be empty).
    """
    ioc, kind = normalize(raw)
    notes: list[str] = []
    vt = abuse = shodan = None

    if kind == "IP" and not is_public_ip(ioc):
        notes.append("Private or reserved address: public threat feeds hold no data for it.")
    else:
        if kind == "Unknown":
            notes.append("Unrecognised format; queried VirusTotal as free text.")
        vt = sources.query_virustotal(ioc, keys.get("vt", ""))
        if kind == "IP":
            abuse = sources.query_abuseipdb(ioc, keys.get("abuseipdb", ""))
            if use_shodan:
                shodan = sources.query_shodan(ioc, keys.get("shodan", ""))

    risk, reasons = score(kind, vt, abuse)
    errors, skipped = [], []
    for field, result in (("vt", vt), ("abuse", abuse), ("shodan", shodan)):
        if result and not result.get("ok"):
            (skipped if result.get("skipped") else errors).append(
                f"{SOURCE_NAMES[field]}: {result.get('error')}"
            )

    return {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "input": (raw or "").strip(),
        "ioc": ioc,
        "type": kind,
        "risk": risk,
        "reasons": reasons,
        "notes": notes,
        "errors": errors,
        "skipped": skipped,
        "vt": vt,
        "abuse": abuse,
        "shodan": shodan,
    }


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
