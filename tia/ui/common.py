"""Shared state, data access and result rendering for the Streamlit pages."""

from __future__ import annotations

import os
from datetime import datetime

import pandas as pd
import streamlit as st

from tia import config
from tia.config import RISK_COLORS
from tia.legacy import import_legacy_files
from tia.scanner import to_frame
from tia.storage import Store
from tia.ui import theme

# key -> (label, name in [apikeys] secrets, environment variable)
KEY_FIELDS = {
    "vt": ("VirusTotal", "VT", "VT_API_KEY"),
    "abuseipdb": ("AbuseIPDB", "AbuseIPDB", "ABUSEIPDB_API_KEY"),
    "shodan": ("Shodan", "Shodan", "SHODAN_API_KEY"),
}

PAGE_SCAN = "views/scan.py"
PAGE_INVESTIGATIONS = "views/investigations.py"
PAGE_REPORTS = "views/reports.py"
PAGE_SETTINGS = "views/settings.py"


def page_link(container, page: str, label: str, icon: str) -> None:
    """st.page_link that degrades to nothing when no navigation is registered
    (e.g. when a page script runs on its own in tests)."""
    try:
        container.page_link(page, label=label, icon=icon, use_container_width=True)
    except st.errors.StreamlitAPIException:
        pass


# -- storage & identity ---------------------------------------------------
@st.cache_resource(show_spinner=False)
def _store_for(path: str) -> Store:
    store = Store(path)
    import_legacy_files(store, config.BASE_DIR)
    return store


def get_store() -> Store:
    return _store_for(str(config.db_path()))


def current_user() -> dict | None:
    return st.session_state.get("user")


def username() -> str:
    u = current_user()
    return u["username"] if u else ""


def is_admin() -> bool:
    u = current_user()
    return bool(u and u.get("role") == "admin")


def history_scope() -> str | None:
    """Admins see every user's scans; analysts only their own."""
    return None if is_admin() else username()


def _has_secrets() -> bool:
    """True if a secrets.toml exists. Checking first avoids Streamlit's on-page
    'No secrets found' error when the app runs without one."""
    try:
        return bool(st.secrets.load_if_toml_exists())
    except AttributeError:  # older/newer Streamlit without this helper
        return True
    except Exception:
        return False


def _secrets_section(name: str) -> dict:
    if not _has_secrets():
        return {}
    try:
        if name in st.secrets:
            return dict(st.secrets[name])
    except Exception:
        pass
    return {}


def secret_users() -> list[dict]:
    return [dict(u) for u in _secrets_section("credentials").get("users", [])]


def resolve_keys(store: Store) -> dict[str, tuple[str, str]]:
    """API key and where it comes from. Precedence: secrets > environment > app settings."""
    sec = _secrets_section("apikeys")
    out = {}
    for key, (_, secret_name, env) in KEY_FIELDS.items():
        if sec.get(secret_name):
            out[key] = (str(sec[secret_name]), "secrets")
        elif os.environ.get(env):
            out[key] = (os.environ[env], "environment")
        elif store.get_setting(f"apikey.{key}"):
            out[key] = (store.get_setting(f"apikey.{key}"), "app settings")
        else:
            out[key] = ("", "not set")
    return out


def api_keys(store: Store) -> dict[str, str]:
    return {k: v for k, (v, _) in resolve_keys(store).items()}


def source_status(store: Store) -> None:
    parts = []
    for key, (value, origin) in resolve_keys(store).items():
        label = KEY_FIELDS[key][0]
        color, state = ("#3fb950", "connected") if value else ("#6e7681", "not configured")
        parts.append(f"<span><span class='ti-dot' style='background:{color}'></span>{label} <span style='color:#6e7681'>· {state}</span></span>")
    st.markdown(f"<div class='ti-source-row'>{''.join(parts)}</div>", unsafe_allow_html=True)


# -- tables ---------------------------------------------------------------
def display_frame(results: list[dict]) -> pd.DataFrame:
    df = to_frame(results)
    if df.empty:
        return df
    return pd.DataFrame(
        {
            "Severity": df["risk"],
            "Indicator": df["ioc"],
            "Type": df["type"],
            "VT detections": pd.to_numeric(df["vt_malicious"], errors="coerce"),
            "Abuse confidence": pd.to_numeric(df["abuse_confidence"], errors="coerce"),
            "Country": df["country"].fillna(""),
            "Open ports": df["open_ports"],
            "Scanned": df["timestamp"],
            "Issues": df["issues"],
        }
    )


COLUMN_CONFIG = {
    "Severity": st.column_config.TextColumn("Severity", width="small"),
    "Indicator": st.column_config.TextColumn("Indicator", width="large"),
    "Type": st.column_config.TextColumn("Type", width="small"),
    "VT detections": st.column_config.NumberColumn("VT detections", help="Engines flagging it as malicious", format="%d"),
    "Abuse confidence": st.column_config.ProgressColumn(
        "Abuse conf.", help="AbuseIPDB confidence score (IPs only)", min_value=0, max_value=100, format="%d%%"
    ),
    "Country": st.column_config.TextColumn("Country", width="small"),
    "Scanned": st.column_config.DatetimeColumn("Scanned", format="YYYY-MM-DD HH:mm"),
    "Issues": st.column_config.TextColumn("Issues", help="Lookup errors such as rate limits"),
}


def _style_severity(value):
    color = RISK_COLORS.get(value)
    return f"color: {color}; font-weight: 600" if color else ""


def show_table(df: pd.DataFrame, **kwargs):
    """st.dataframe with severity-coloured text and the shared column config."""
    if df.empty:
        st.caption("No rows.")
        return None
    style = df.style
    apply = style.map if hasattr(style, "map") else style.applymap
    styler = apply(_style_severity, subset=["Severity"])
    return st.dataframe(styler, hide_index=True, use_container_width=True, column_config=COLUMN_CONFIG, **kwargs)


def csv_bytes(results: list[dict]) -> bytes:
    return to_frame(results).to_csv(index=False).encode("utf-8")


def risk_counts(results: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.get("risk", "Unknown")] = counts.get(r.get("risk", "Unknown"), 0) + 1
    return counts


def summary_pills(results: list[dict]) -> None:
    counts = risk_counts(results)
    pills = "".join(
        f"{theme.severity(r)}<span class='ti-count'>{counts[r]}</span>"
        for r in config.RISK_ORDER if counts.get(r)
    )
    st.markdown(f"<div style='margin:.1rem 0 .9rem'>{pills}</div>", unsafe_allow_html=True)


# -- sessions -------------------------------------------------------------
def session_label(s: dict, show_user: bool) -> str:
    try:
        when = datetime.fromisoformat(s["created_at"]).strftime("%b %d, %H:%M")
    except (TypeError, ValueError):
        when = s.get("created_at", "")
    name = s.get("label") or s.get("kind") or "Scan"
    flag = f" · {s['high']} high" if s.get("high") else ""
    who = f" · {s['username']}" if show_user else ""
    return f"{when} · {name} · {s['total']} IOC{'s' if s['total'] != 1 else ''}{flag}{who}"


def session_picker(store: Store, key: str) -> tuple[str | None, list[dict]]:
    sessions = store.list_sessions(history_scope())
    if not sessions:
        return None, sessions
    ids = [s["id"] for s in sessions]
    labels = {s["id"]: session_label(s, is_admin()) for s in sessions}
    wanted = st.session_state.get("selected_session")
    index = ids.index(wanted) if wanted in ids else 0
    sid = st.selectbox("Investigation", ids, index=index, format_func=labels.get, key=key)
    st.session_state["selected_session"] = sid
    return sid, sessions


# -- result detail --------------------------------------------------------
def _level_color(value: int, high: int, medium: int) -> str:
    if value >= high:
        return RISK_COLORS["High"]
    if value >= medium:
        return RISK_COLORS["Medium"]
    if value > 0:
        return RISK_COLORS["Low"]
    return RISK_COLORS["Legitimate"]


def _link(url: str | None, label: str) -> str:
    return f"<div class='ti-link'><a href='{theme.esc(url)}' target='_blank'>{label} ↗</a></div>" if url else ""


def _problem(name: str, result: dict) -> str:
    tag = "skipped" if result.get("skipped") else "error"
    return theme.card(name, f"<div class='ti-sub' style='color:#d29922'>{theme.esc(result.get('error'))}</div>", tag)


def _vt_card(vt: dict | None) -> str:
    if not vt:
        return theme.card("VirusTotal", "<div class='ti-sub'>Not queried for this indicator.</div>", "n/a")
    if not vt.get("ok"):
        return _problem("VirusTotal", vt)
    if not vt.get("found"):
        return theme.card("VirusTotal", "<div class='ti-sub'>No record of this indicator.</div>", "not found")
    total = vt.get("total") or 0
    mal = vt.get("malicious", 0)
    color = _level_color(mal, 10, 4)
    body = (
        f"<div><span class='ti-big' style='color:{color}'>{mal}</span>"
        f"<span class='ti-sub'> / {total} security vendors flagged this as malicious</span></div>"
        + theme.bar(mal / total if total else 0, color)
        + theme.stat("Suspicious", vt.get("suspicious", 0))
        + theme.stat("Harmless", vt.get("harmless", 0))
        + theme.stat("Undetected", vt.get("undetected", 0))
        + theme.stat("Community reputation", vt.get("reputation"))
    )
    if vt.get("tags"):
        body += "<div style='margin-top:8px'>" + "".join(f"<span class='ti-chip'>{theme.esc(t)}</span>" for t in vt["tags"][:8]) + "</div>"
    body += _link(vt.get("link"), "View on VirusTotal")
    return theme.card("VirusTotal", body, "v3 API")


def _abuse_card(abuse: dict | None) -> str:
    if not abuse:
        return theme.card("AbuseIPDB", "<div class='ti-sub'>Applies to public IP addresses only.</div>", "n/a")
    if not abuse.get("ok"):
        return _problem("AbuseIPDB", abuse)
    c = abuse.get("confidence", 0)
    color = _level_color(c, 80, 30)
    body = (
        f"<div><span class='ti-big' style='color:{color}'>{c}%</span>"
        f"<span class='ti-sub'> confidence of abuse</span></div>"
        + theme.bar(c / 100, color)
        + theme.stat("Reports (90 days)", abuse.get("reports"))
        + theme.stat("Distinct reporters", abuse.get("distinct_users"))
        + theme.stat("Whitelisted", "Yes" if abuse.get("whitelisted") else "No")
        + theme.stat("Country", abuse.get("country"))
        + theme.stat("ISP", abuse.get("isp"))
        + theme.stat("Usage type", abuse.get("usage"))
        + theme.stat("Last reported", (abuse.get("last_reported") or "")[:19].replace("T", " "))
    )
    body += _link(abuse.get("link"), "View on AbuseIPDB")
    return theme.card("AbuseIPDB", body, "v2 API")


def _shodan_card(sh: dict | None) -> str:
    if not sh:
        return theme.card("Shodan", "<div class='ti-sub'>Applies to public IP addresses only.</div>", "n/a")
    if not sh.get("ok"):
        return _problem("Shodan", sh)
    if not sh.get("found"):
        return theme.card("Shodan", "<div class='ti-sub'>No banner data for this host.</div>", "not found")
    ports = "".join(f"<span class='ti-chip ti-mono'>{p}</span>" for p in sh.get("ports", [])) or "<span class='ti-sub'>None observed</span>"
    vulns = sh.get("vulns", [])
    body = (
        f"<div class='ti-sub' style='margin-bottom:4px'>Open ports ({len(sh.get('ports', []))})</div>"
        f"<div style='margin-bottom:8px'>{ports}</div>"
        + theme.stat("Organisation", sh.get("org"))
        + theme.stat("ISP", sh.get("isp"))
        + theme.stat("Operating system", sh.get("os"))
        + theme.stat("Country", sh.get("country"))
        + theme.stat("Hostnames", ", ".join(sh.get("hostnames", [])[:3]))
        + theme.stat("Known CVEs", len(vulns))
        + theme.stat("Last scanned", (sh.get("last_update") or "")[:10])
    )
    if vulns:
        body += "<div style='margin-top:6px'>" + "".join(f"<span class='ti-chip ti-mono'>{theme.esc(v)}</span>" for v in vulns[:6]) + "</div>"
    body += _link(sh.get("link"), "View on Shodan")
    return theme.card("Shodan", body, "host API")


def render_result(result: dict) -> None:
    risk = result.get("risk", "Unknown")
    sources = [result.get(k) for k in ("vt", "abuse", "shodan") if result.get(k)]
    answered = sum(1 for s in sources if s.get("ok"))
    vt = result.get("vt") or {}
    detections = f"{vt.get('malicious', 0)}/{vt.get('total', 0)}" if vt.get("ok") and vt.get("found") else "—"

    items = "".join(f"<li>{theme.esc(r)}</li>" for r in result.get("reasons", []))
    items += "".join(f"<li class='ti-note'>{theme.esc(n)}</li>" for n in result.get("notes", []))
    items += "".join(f"<li class='ti-warn'>{theme.esc(e)}</li>" for e in result.get("errors", []) + result.get("skipped", []))
    shown_input = result.get("input") if result.get("input") and result.get("input") != result.get("ioc") else ""
    refanged = f"<span>Input <b class='ti-mono'>{theme.esc(shown_input)}</b></span>" if shown_input else ""

    st.markdown(
        "<div class='ti-card'><div class='ti-verdict'><div>"
        f"{theme.severity(risk, large=True)}"
        f"<div class='ti-ioc ti-mono'>{theme.esc(result.get('ioc'))}</div>"
        "<div class='ti-meta'>"
        f"<span>Type <b>{theme.esc(result.get('type'))}</b></span>"
        f"<span>Scanned <b>{theme.esc(str(result.get('timestamp', '')).replace('T', ' '))}</b></span>"
        f"<span>Sources responded <b>{answered}/{len(sources)}</b></span>{refanged}"
        "</div></div>"
        f"<div class='ti-score'><div class='n'>{detections}</div><div class='l'>VT detections</div></div>"
        f"</div><ul class='ti-reasons'>{items}</ul></div>",
        unsafe_allow_html=True,
    )
    st.write("")
    c1, c2, c3 = st.columns(3)
    c1.markdown(_vt_card(result.get("vt")), unsafe_allow_html=True)
    c2.markdown(_abuse_card(result.get("abuse")), unsafe_allow_html=True)
    c3.markdown(_shodan_card(result.get("shodan")), unsafe_allow_html=True)

    vendor_hits = vt.get("detections") or []
    if vendor_hits:
        with st.expander(f"Vendor detections ({len(vendor_hits)})"):
            st.dataframe(
                pd.DataFrame(vendor_hits).rename(columns={"engine": "Vendor", "category": "Category", "result": "Result"}),
                hide_index=True, use_container_width=True,
            )
    with st.expander("Raw API responses"):
        tabs = st.tabs(["VirusTotal", "AbuseIPDB", "Shodan"])
        for tab, field in zip(tabs, ("vt", "abuse", "shodan")):
            with tab:
                st.json(result.get(field) or {"note": "not queried"}, expanded=False)
