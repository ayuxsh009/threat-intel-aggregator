"""Lookup service behind the browser extension.

* Normalises what the browser sends (a URL or hostname) to one host.
* Answers from the database when a recent result exists (default 24 h).
* Otherwise queues the host and scans it in a background thread, spacing
  lookups so free API keys are not rate limited.
* Always applies the *current* analyst verdict, even to cached results.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import deque
from datetime import datetime
from urllib.parse import urlsplit

from tia import keys as keymod
from tia.ioc import classify
from tia.scanner import scan_ioc
from tia.threatscore import assess

LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".home.arpa", ".corp", ".test",
                  ".invalid", ".example")
SESSION_KIND = "extension"


def normalize_target(target: str) -> tuple[str | None, str]:
    """Return ``(host, "")`` for a checkable host, or ``(None, reason)``."""
    raw = (target or "").strip()
    if not raw:
        return None, "Nothing to check."
    if "://" not in raw:
        raw = "http://" + raw
    try:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return None, "Not a valid address."
    if parts.scheme not in ("http", "https"):
        return None, f"{parts.scheme}: pages are not checked."
    if not host:
        return None, "No host name."
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            return None, "Private or reserved address."
        return str(ip), ""
    except ValueError:
        pass
    if host.startswith("www."):
        host = host[4:]
    if host == "localhost" or "." not in host or host.endswith(LOCAL_SUFFIXES):
        return None, "Local or internal host."
    if classify(host) != "Domain":
        return None, "Not a public domain name."
    return host, ""


def _age_seconds(timestamp: str | None) -> float | None:
    try:
        return (datetime.now() - datetime.fromisoformat(str(timestamp))).total_seconds()
    except (TypeError, ValueError):
        return None


def summarize(result: dict, verdict: dict | None) -> dict:
    """Compact view for the extension, re-scored with the current analyst verdict."""
    verdict_info = ({k: verdict.get(k) for k in ("verdict", "note", "username", "updated_at")}
                    if verdict else None)
    outcome = assess(result.get("type"), result.get("vt"), result.get("abuse"), result.get("shodan"),
                     result.get("threatfox"), result.get("urlhaus"), result.get("rdap"),
                     result.get("sightings"), verdict_info)
    vt, abuse = result.get("vt") or {}, result.get("abuse") or {}
    tf, uh, rdap = result.get("threatfox") or {}, result.get("urlhaus") or {}, result.get("rdap") or {}
    seen = result.get("sightings") or {}
    return {
        "ioc": result.get("ioc"),
        "type": result.get("type"),
        "risk": outcome["risk"],
        "rule_risk": outcome["rule_risk"],
        "score": outcome["score"],
        "factors": outcome["factors"],
        "reasons": outcome["reasons"][:8],
        "errors": result.get("errors") or [],
        "skipped": result.get("skipped") or [],
        "changes": result.get("changes") or [],
        "verdict": verdict_info,
        "scanned_at": result.get("timestamp"),
        "age_seconds": _age_seconds(result.get("timestamp")),
        "vt": ({"malicious": vt.get("malicious", 0), "suspicious": vt.get("suspicious", 0),
                "total": vt.get("total", 0), "link": vt.get("link")} if vt.get("ok") and vt.get("found") else None),
        "abuse": ({"confidence": abuse.get("confidence"), "reports": abuse.get("reports"),
                   "country": abuse.get("country"), "isp": abuse.get("isp")} if abuse.get("ok") else None),
        "threatfox": ({"families": tf.get("families"), "confidence": tf.get("confidence")}
                      if tf.get("ok") and tf.get("found") else None),
        "urlhaus": ({"count": uh.get("count"), "online": uh.get("online")} if uh.get("ok") and uh.get("found") else None),
        "rdap": ({"domain": rdap.get("domain"), "age_days": rdap.get("age_days"), "registered": rdap.get("registered"),
                  "registrar": rdap.get("registrar")} if rdap.get("ok") and rdap.get("found") else None),
        "sightings": {"count": seen.get("count", 0), "first_seen": seen.get("first_seen"),
                      "worst_risk": seen.get("worst_risk")},
    }


class LookupService:
    def __init__(self, store, *, username: str = "browser", ttl_hours: float = 24.0,
                 min_interval: float | None = None, secrets_loader=keymod.load_secrets_file,
                 start_worker: bool = True):
        self.store = store
        self.username = username
        self.ttl = ttl_hours * 3600
        self._min_interval = min_interval
        self._secrets_loader = secrets_loader
        self._queue: deque[str] = deque()
        self._state: dict[str, dict] = {}  # host -> {"status": queued|running|error, "error": ...}
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._last_scan = 0.0
        self._stop = False
        self._thread = None
        if start_worker:
            self._thread = threading.Thread(target=self._run, name="ti-lookup-worker", daemon=True)
            self._thread.start()

    # -- configuration -------------------------------------------------
    def secrets(self) -> dict:
        return self._secrets_loader() or {}

    def keys(self) -> dict[str, str]:
        resolved = keymod.resolve(self.store, self.secrets().get("apikeys") or {})
        return {k: v for k, (v, _) in resolved.items()}

    def min_interval(self) -> float:
        """Seconds between lookups. VirusTotal's free tier allows 4 per minute."""
        if self._min_interval is not None:
            return self._min_interval
        return 15.5 if self.keys().get("vt") else 0.0

    def token(self) -> str:
        return keymod.api_token(self.store, self.secrets())[0]

    # -- lookups -------------------------------------------------------
    def latest(self, host: str) -> dict | None:
        hist = self.store.ioc_history(host, limit=1)
        return hist[0]["result"] if hist else None

    def lookup(self, target: str, *, force: bool = False) -> dict:
        host, reason = normalize_target(target)
        if not host:
            return {"status": "skipped", "target": target, "reason": reason}
        verdict = self.store.get_verdict(host)
        cached = self.latest(host)
        age = _age_seconds(cached.get("timestamp")) if cached else None
        fresh = cached is not None and age is not None and age < self.ttl

        with self._lock:
            state = self._state.get(host)
            if fresh and not force and not state:
                return {"status": "ready", "host": host, "cached": True, "result": summarize(cached, verdict)}
            if not state or state.get("status") == "error":
                if state and state.get("status") == "error" and not force:
                    self._state.pop(host, None)
                    return {"status": "error", "host": host, "error": state.get("error"),
                            "result": summarize(cached, verdict) if cached else None}
                self._queue.append(host)
                self._state[host] = {"status": "queued", "since": time.time()}
                self._wake.set()
            state = self._state.get(host, {})
            position = list(self._queue).index(host) + 1 if host in self._queue else 0

        wait = max(0, position - 1) * self.min_interval() + max(0.0, self._last_scan + self.min_interval() - time.time())
        out = {"status": "pending", "host": host, "state": state.get("status", "queued"), "position": position,
               "eta_seconds": round(wait), "verdict": verdict and {k: verdict[k] for k in ("verdict", "note", "username")}}
        if cached:  # show the older result while a fresh one is fetched
            out["stale"] = summarize(cached, verdict)
        return out

    def set_verdict(self, target: str, verdict: str | None, note: str = "", username: str = "") -> dict:
        host, reason = normalize_target(target)
        if not host:
            return {"status": "skipped", "target": target, "reason": reason}
        if verdict in ("malicious", "benign"):
            self.store.set_verdict(host, verdict, ioc_type=classify(host), note=note,
                                   username=username or self.username)
        else:
            self.store.delete_verdict(host)
        return self.lookup(host)

    def queue_size(self) -> int:
        with self._lock:
            return len(self._queue)

    # -- worker --------------------------------------------------------
    def _session_id(self) -> str:
        label = f"Browser extension · {datetime.now():%Y-%m-%d}"
        sid = self.store.find_session(self.username, SESSION_KIND, label)
        return sid or self.store.create_session(self.username, SESSION_KIND, label)

    def process_one(self) -> str | None:
        """Scan the next queued host (respecting the minimum interval). Returns the host or None."""
        with self._lock:
            if not self._queue:
                return None
            host = self._queue[0]
            self._state[host] = {"status": "running", "since": time.time()}
        delay = self._last_scan + self.min_interval() - time.time()
        if delay > 0:
            time.sleep(delay)
        try:
            result = scan_ioc(host, self.keys(), use_shodan=False, store=self.store)
            self.store.add_scan(self._session_id(), self.username, result)
            with self._lock:
                self._state.pop(host, None)
        except Exception as exc:  # never let one failure stop the worker
            with self._lock:
                self._state[host] = {"status": "error", "error": str(exc)}
        finally:
            self._last_scan = time.time()
            with self._lock:
                if self._queue and self._queue[0] == host:
                    self._queue.popleft()
        return host

    def _run(self) -> None:
        while not self._stop:
            if self.process_one() is None:
                self._wake.wait(timeout=5)
                self._wake.clear()

    def stop(self) -> None:
        self._stop = True
        self._wake.set()
