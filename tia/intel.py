"""Local intelligence: what this workspace already knows about an indicator.

Public feeds only describe the world. These helpers describe *your* history
with an indicator (sightings) and what changed since you last looked (diff).
"""

from __future__ import annotations

from .scoring import _SEVERITY


def sightings(history: list[dict]) -> dict:
    """Summarise earlier scans of one indicator.

    ``history`` holds rows from :meth:`Store.ioc_history`, newest first, each
    with ``session_id``, ``label``, ``created_at`` and ``result``.
    """
    if not history:
        return {"count": 0}
    results = [h["result"] for h in history]
    stamps = sorted(str(r.get("timestamp") or "") for r in results if r.get("timestamp"))
    rated = [r.get("risk") for r in results if r.get("risk") in _SEVERITY]
    sessions: dict[str, dict] = {}
    for h in history:
        sessions.setdefault(h["session_id"], {"id": h["session_id"], "label": h.get("label") or "Scan",
                                              "created_at": h.get("created_at")})
    return {
        "count": len(results),
        "first_seen": stamps[0] if stamps else None,
        "last_seen": stamps[-1] if stamps else None,
        "investigations": len(sessions),
        "sessions": list(sessions.values())[:10],
        "last_risk": results[0].get("risk"),
        "last_score": results[0].get("score"),
        "worst_risk": max(rated, key=_SEVERITY.__getitem__) if rated else None,
    }


def _ok(d: dict | None) -> bool:
    return bool(d and d.get("ok"))


def diff(previous: dict | None, current: dict) -> list[str]:
    """Human-readable changes between two scans of the same indicator."""
    if not previous:
        return []
    out: list[str] = []
    if previous.get("risk") != current.get("risk"):
        out.append(f"Severity {previous.get('risk')} → {current.get('risk')}")
    ps, cs = previous.get("score"), current.get("score")
    if isinstance(ps, int) and isinstance(cs, int) and abs(cs - ps) >= 5:
        out.append(f"Threat score {ps} → {cs}")

    pv, cv = previous.get("vt"), current.get("vt")
    if _ok(pv) and _ok(cv) and pv.get("malicious", 0) != cv.get("malicious", 0):
        out.append(f"VirusTotal detections {pv.get('malicious', 0)} → {cv.get('malicious', 0)}")

    pa, ca = previous.get("abuse"), current.get("abuse")
    if _ok(pa) and _ok(ca) and abs(pa.get("confidence", 0) - ca.get("confidence", 0)) >= 10:
        out.append(f"AbuseIPDB confidence {pa.get('confidence', 0)}% → {ca.get('confidence', 0)}%")

    psh, csh = previous.get("shodan"), current.get("shodan")
    if _ok(psh) and _ok(csh):
        before, after = set(psh.get("ports") or []), set(csh.get("ports") or [])
        if after - before:
            out.append("Newly open ports: " + ", ".join(str(p) for p in sorted(after - before)))
        if before - after:
            out.append("Ports closed: " + ", ".join(str(p) for p in sorted(before - after)))
        new_cves = set(csh.get("vulns") or []) - set(psh.get("vulns") or [])
        if new_cves:
            out.append("New CVEs: " + ", ".join(sorted(new_cves)[:5]))

    for field, name in (("threatfox", "ThreatFox"), ("urlhaus", "URLhaus")):
        p, c = previous.get(field), current.get(field)
        if _ok(p) and _ok(c) and bool(p.get("found")) != bool(c.get("found")):
            out.append(f"Now listed in {name}" if c.get("found") else f"No longer listed in {name}")
    return out
