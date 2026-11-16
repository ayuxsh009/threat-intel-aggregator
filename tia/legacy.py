"""One-time import of data from version 1 JSON files.

Version 1 kept users, API keys and scan history in configure.json,
apikeys.json and scan_log.json next to the app. If those files exist when the
database is first created, their contents are imported (passwords hashed,
scans re-scored with the current rules). The JSON files are left untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

from .auth import hash_password, validate_username
from .scoring import score

_FLAG = "legacy_import_done"


def _load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _convert_scan(old: dict) -> dict:
    vt_old = old.get("vt") if isinstance(old.get("vt"), dict) else {}
    ab_old = old.get("abuse") if isinstance(old.get("abuse"), dict) else {}
    sh_old = old.get("shodan") if isinstance(old.get("shodan"), dict) else None

    vt = {"ok": "error" not in vt_old and bool(vt_old), "found": bool(vt_old.get("vt_data")),
          "malicious": int(vt_old.get("vt_malicious", 0) or 0),
          "suspicious": int(vt_old.get("vt_suspicious", 0) or 0),
          "undetected": int(vt_old.get("vt_undetected", 0) or 0),
          "total": int(sum((vt_old.get("vt_data") or {}).values()) or 0), "detections": []}
    if "error" in vt_old:
        vt["error"] = vt_old["error"]

    abuse = None
    if old.get("type") == "IP" and "abuseConfidenceScore" in ab_old:
        abuse = {"ok": True, "confidence": int(ab_old.get("abuseConfidenceScore") or 0),
                 "reports": int(ab_old.get("totalReports") or 0),
                 "whitelisted": bool(ab_old.get("isWhitelisted")),
                 "country": ab_old.get("countryCode"), "isp": ab_old.get("isp")}
    shodan = None
    if sh_old is not None:
        shodan = ({"ok": False, "error": sh_old["error"]} if "error" in sh_old
                  else {"ok": True, "found": True, "ports": sh_old.get("ports", []), "org": sh_old.get("org")})

    kind = old.get("type", "Unknown")
    risk, reasons = score(kind, vt, abuse)
    ts = str(old.get("timestamp", "")).replace(" ", "T")
    return {"timestamp": ts, "input": old.get("ioc", ""), "ioc": old.get("ioc", ""), "type": kind,
            "risk": risk, "reasons": reasons, "notes": ["Imported from version 1 scan history."],
            "errors": [vt["error"]] if vt.get("error") else [], "skipped": [],
            "vt": vt, "abuse": abuse, "shodan": shodan}


def import_legacy_files(store, folder: Path) -> None:
    if store.get_setting(_FLAG):
        return
    folder = Path(folder)

    cfg = _load(folder / "configure.json")
    if isinstance(cfg, dict):
        for u in cfg.get("users", []):
            name, pw = str(u.get("username", "")), u.get("password")
            if pw and not validate_username(name) and not store.get_user(name):
                store.add_user(name, hash_password(str(pw)), "admin")

    keys = _load(folder / "apikeys.json")
    if isinstance(keys, dict):
        for old, new in (("VT", "vt"), ("AbuseIPDB", "abuseipdb"), ("Shodan", "shodan")):
            if keys.get(old) and not store.get_setting(f"apikey.{new}"):
                store.set_setting(f"apikey.{new}", str(keys[old]))

    log = _load(folder / "scan_log.json")
    if isinstance(log, list) and log:
        groups: dict[str, list[dict]] = {}
        for entry in log:
            if isinstance(entry, dict):
                groups.setdefault(entry.get("scan_session") or entry.get("session") or "legacy", []).append(entry)
        for entries in groups.values():
            converted = [_convert_scan(e) for e in entries]
            first = min((c["timestamp"] for c in converted), default=None)
            sid = store.create_session("legacy-import", "imported", "Imported from v1", created_at=first)
            store.add_scans(sid, "legacy-import", converted)

    store.set_setting(_FLAG, "1")
