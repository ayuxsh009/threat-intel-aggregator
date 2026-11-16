"""Risk scoring.

Each source gives its own level and the IOC takes the most severe one:

* VirusTotal malicious engines: >=10 High, 4-9 Medium, 1-3 Low, 0 Legitimate.
* AbuseIPDB confidence score (IPs only): >=80 High, 30-79 Medium, 1-29 Low,
  0 Legitimate. A whitelisted IP cancels the AbuseIPDB level, but never
  overrides VirusTotal detections.
* If no source returned data (missing keys, errors, rate limits) the verdict
  is "Unknown", never "Legitimate".
"""

from __future__ import annotations

_SEVERITY = {"Legitimate": 0, "Low": 1, "Medium": 2, "High": 3}


def vt_level(malicious: int) -> str:
    m = malicious or 0
    if m >= 10:
        return "High"
    if m >= 4:
        return "Medium"
    if m >= 1:
        return "Low"
    return "Legitimate"


def abuse_level(confidence: int) -> str:
    c = confidence or 0
    if c >= 80:
        return "High"
    if c >= 30:
        return "Medium"
    if c >= 1:
        return "Low"
    return "Legitimate"


def score(ioc_type: str, vt: dict | None, abuse: dict | None) -> tuple[str, list[str]]:
    """Return (risk, reasons)."""
    levels: list[str] = []
    reasons: list[str] = []

    if vt and vt.get("ok"):
        m = vt.get("malicious", 0)
        levels.append(vt_level(m))
        if not vt.get("found", True):
            reasons.append("VirusTotal: no record of this indicator")
        else:
            s = vt.get("suspicious", 0)
            extra = f", {s} suspicious" if s else ""
            reasons.append(f"VirusTotal: {m} of {vt.get('total', 0)} engines flag it as malicious{extra}")

    if ioc_type == "IP" and abuse and abuse.get("ok"):
        c, n = abuse.get("confidence", 0), abuse.get("reports", 0)
        if abuse.get("whitelisted"):
            levels.append("Legitimate")
            reasons.append(f"AbuseIPDB: whitelisted ({n} reports ignored)")
        else:
            levels.append(abuse_level(c))
            reasons.append(f"AbuseIPDB: {c}% abuse confidence from {n} reports")

    if not levels:
        return "Unknown", ["No threat-intel source returned data for this indicator"]
    return max(levels, key=_SEVERITY.__getitem__), reasons
