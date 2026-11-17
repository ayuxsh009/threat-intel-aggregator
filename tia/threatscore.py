"""Explainable 0-100 threat score.

The rule-based verdict in :mod:`tia.scoring` answers "what do the feeds say?".
This score adds context the feeds don't give on their own: how much evidence
agrees, what the host exposes, how new a domain is, and what this workspace
has already seen. Every point comes from a named factor so analysts can see
exactly why an indicator scored what it did.

The score can raise the final severity (strong combined evidence) but never
lowers it below the rule-based verdict. An analyst verdict overrides both.
"""

from __future__ import annotations

from .scoring import _SEVERITY, score as rule_score

# Services that should rarely face the internet; exposure is a common entry point.
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB", 1433: "MSSQL",
    2375: "Docker API", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB",
}

SCORE_BANDS = [(70, "High"), (40, "Medium"), (15, "Low"), (0, "Legitimate")]


def band(points: int) -> str:
    for floor, level in SCORE_BANDS:
        if points >= floor:
            return level
    return "Legitimate"


def _factor(factors: list, points: float, label: str, source: str) -> None:
    pts = int(round(points))
    if pts:
        factors.append({"points": pts, "label": label, "source": source})


def compute_factors(kind: str, vt=None, abuse=None, shodan=None, threatfox=None, urlhaus=None,
                    rdap=None, sightings=None) -> list[dict]:
    f: list[dict] = []

    if vt and vt.get("ok") and vt.get("found"):
        m, s, total = vt.get("malicious", 0), vt.get("suspicious", 0), vt.get("total", 0)
        _factor(f, min(45, m * 4.5), f"{m}/{total} VirusTotal engines flag it as malicious", "VirusTotal")
        _factor(f, min(8, s * 2), f"{s} engine{'s' if s != 1 else ''} mark{'' if s != 1 else 's'} it suspicious", "VirusTotal")
        rep = vt.get("reputation")
        if isinstance(rep, (int, float)) and rep <= -10:
            _factor(f, 5, f"Negative community reputation ({rep})", "VirusTotal")

    if kind == "IP" and abuse and abuse.get("ok"):
        if abuse.get("whitelisted"):
            _factor(f, -15, "Whitelisted by AbuseIPDB (known service)", "AbuseIPDB")
        else:
            c, n = abuse.get("confidence", 0), abuse.get("reports", 0)
            _factor(f, c * 0.35, f"{c}% AbuseIPDB abuse confidence", "AbuseIPDB")
            if n >= 50:
                _factor(f, 5, f"High report volume ({n} reports in 90 days)", "AbuseIPDB")

    if shodan and shodan.get("ok") and shodan.get("found"):
        exposed = [f"{RISKY_PORTS[p]} ({p})" for p in shodan.get("ports", []) if p in RISKY_PORTS]
        if exposed:
            _factor(f, min(15, 5 * len(exposed)), "Exposes " + ", ".join(exposed[:4]), "Shodan")
        vulns = shodan.get("vulns") or []
        if vulns:
            _factor(f, min(15, 3 * len(vulns)), f"{len(vulns)} known CVE(s) on this host", "Shodan")

    if threatfox and threatfox.get("ok") and threatfox.get("found"):
        fam = ", ".join(threatfox.get("families") or []) or "malware"
        _factor(f, 40, f"Listed in ThreatFox as {fam} infrastructure", "ThreatFox")

    if urlhaus and urlhaus.get("ok") and urlhaus.get("found"):
        if urlhaus.get("online"):
            _factor(f, 35, f"{urlhaus['online']} malware URL(s) online now in URLhaus", "URLhaus")
        else:
            _factor(f, 20, f"Historic malware distribution in URLhaus ({urlhaus.get('count', 0)} URLs)", "URLhaus")

    if rdap and rdap.get("ok") and rdap.get("found") and rdap.get("age_days") is not None:
        age = rdap["age_days"]
        if age < 30:
            _factor(f, 15, f"Domain registered {age} days ago", "RDAP")
        elif age < 180:
            _factor(f, 7, f"Young domain ({age} days old)", "RDAP")

    if sightings and sightings.get("count"):
        worst = sightings.get("worst_risk")
        if worst in ("High", "Medium"):
            _factor(f, 10, f"Previously rated {worst} in this workspace", "History")
        if sightings.get("investigations", 0) >= 3:
            _factor(f, 3, f"Recurring: seen in {sightings['investigations']} investigations", "History")

    f.sort(key=lambda x: -x["points"])
    return f


def assess(kind: str, vt=None, abuse=None, shodan=None, threatfox=None, urlhaus=None,
           rdap=None, sightings=None, verdict=None) -> dict:
    """Combine the rule-based verdict, the factor score and any analyst verdict."""
    rule_risk, reasons = rule_score(kind, vt, abuse, threatfox, urlhaus)
    factors = compute_factors(kind, vt, abuse, shodan, threatfox, urlhaus, rdap, sightings)
    points = max(0, min(100, sum(x["points"] for x in factors)))

    risk = rule_risk
    if rule_risk != "Unknown":
        scored = band(points)
        if _SEVERITY[scored] > _SEVERITY[rule_risk]:
            reasons = reasons + [f"Combined evidence score {points}/100 raised severity from {rule_risk} to {scored}"]
            risk = scored

    if verdict and verdict.get("verdict") in ("malicious", "benign"):
        who = verdict.get("username") or "an analyst"
        note = f": {verdict['note']}" if verdict.get("note") else ""
        if verdict["verdict"] == "malicious":
            risk = "High"
            reasons = [f"Analyst verdict: confirmed malicious by {who}{note}"] + reasons
        else:
            risk = "Legitimate"
            reasons = [f"Analyst verdict: false positive, marked benign by {who}{note}"] + reasons

    return {"risk": risk, "rule_risk": rule_risk, "score": points, "factors": factors, "reasons": reasons}
