"""Shared state, data access and result rendering for the Streamlit pages."""

from __future__ import annotations

import os
from datetime import datetime

import pandas as pd
import streamlit as st

from tia import config
from tia.config import RISK_COLORS, RISK_ICONS
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
        if value:
            parts.append(f"<span class='ti-source'><b style='color:#22c55e'>●</b> {label}</span>")
        else:
            parts.append(f"<span class='ti-source'><b style='color:#64748b'>○</b> {label} · no key</span>")
    st.markdown(f"<div class='ti-source-row'>{''.join(parts)}</div>", unsafe_allow_html=True)


# -- tables ---------------------------------------------------------------
def display_frame(results: list[dict]) -> pd.DataFrame:
    df = to_frame(results)
    if df.empty:
        return df
    return pd.DataFrame(
        {
            "Risk": [f"{RISK_ICONS.get(r, '')} {r}" for r in df["risk"]],
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
    "Risk": st.column_config.TextColumn("Risk", width="medium"),
    "Indicator": st.column_config.TextColumn("Indicator", width="large"),
    "Type": st.column_config.TextColumn("Type", width="small"),
    "VT detections": st.column_config.NumberColumn("VT detections", help="Engines flagging it as malicious", format="%d"),
    "Abuse confidence": st.column_config.ProgressColumn(
        "Abuse confidence", help="AbuseIPDB confidence score (IPs only)", min_value=0, max_value=100, format="%d%%"
    ),
    "Scanned": st.column_config.DatetimeColumn("Scanned", format="MMM D, HH:mm"),
    "Issues": st.column_config.TextColumn("Issues", help="Lookup errors such as rate limits"),
}


def csv_bytes(results: list[dict]) -> bytes:
    return to_frame(results).to_csv(index=False).encode("utf-8")


def risk_counts(results: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.get("risk", "Unknown")] = counts.get(r.get("risk", "Unknown"), 0) + 1
    return counts


def summary_pills(results: list[dict]) -> None:
    counts = risk_counts(results)
    pills = " ".join(
        f"{theme.risk_pill(r)}<span style='margin:0 12px 0 6px;color:#e2e8f0;font-weight:700'>{counts[r]}</span>"
        for r in config.RISK_ORDER if counts.get(r)
    )
    st.markdown(f"<div style='margin:.2rem 0 .8rem'>{pills}</div>", unsafe_allow_html=True)


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
def _vt_card(vt: dict | None) -> str:
    title = "🧪 VirusTotal"
    if not vt:
        return theme.card(title, "<div class='ti-sub'>Not queried for this indicator.</div>")
    if not vt.get("ok"):
        return theme.card(title, f"<div class='ti-sub ti-warn'>{theme.esc(vt.get('error'))}</div>")
    if not vt.get("found"):
        return theme.card(title, "<div class='ti-sub'>No record found on VirusTotal.</div>")
    total = vt.get("total") or 0
    mal = vt.get("malicious", 0)
    color = RISK_COLORS["High"] if mal >= 10 else RISK_COLORS["Medium"] if mal >= 4 else RISK_COLORS["Low"] if mal else RISK_COLORS["Legitimate"]
    body = (
        f"<div style='display:flex;align-items:baseline;gap:6px'><span style='font-size:1.8rem;font-weight:800;color:{color}'>{mal}</span>"
        f"<span class='ti-sub'>/ {total} engines malicious</span></div>"
        + theme.bar(mal / total if total else 0, color)
        + theme.stat("Suspicious", vt.get("suspicious", 0))
        + theme.stat("Harmless", vt.get("harmless", 0))
        + theme.stat("Undetected", vt.get("undetected", 0))
        + theme.stat("Reputation", vt.get("reputation"))
    )
    if vt.get("tags"):
        body += "<div style='margin-top:8px'>" + "".join(f"<span class='ti-chip'>{theme.esc(t)}</span>" for t in vt["tags"][:8]) + "</div>"
    if vt.get("link"):
        body += f"<div style='margin-top:10px'><a href='{theme.esc(vt['link'])}' target='_blank'>Open in VirusTotal ↗</a></div>"
    return theme.card(title, body)


def _abuse_card(abuse: dict | None) -> str:
    title = "🚩 AbuseIPDB"
    if not abuse:
        return theme.card(title, "<div class='ti-sub'>Only used for public IP addresses.</div>")
    if not abuse.get("ok"):
        return theme.card(title, f"<div class='ti-sub ti-warn'>{theme.esc(abuse.get('error'))}</div>")
    c = abuse.get("confidence", 0)
    color = RISK_COLORS["High"] if c >= 80 else RISK_COLORS["Medium"] if c >= 30 else RISK_COLORS["Low"] if c else RISK_COLORS["Legitimate"]
    body = (
        f"<div style='display:flex;align-items:baseline;gap:6px'><span style='font-size:1.8rem;font-weight:800;color:{color}'>{c}%</span>"
        f"<span class='ti-sub'>abuse confidence</span></div>"
        + theme.bar(c / 100, color)
        + theme.stat("Reports (90 days)", abuse.get("reports"))
        + theme.stat("Reporters", abuse.get("distinct_users"))
        + theme.stat("Whitelisted", "Yes" if abuse.get("whitelisted") else "No")
        + theme.stat("Country", abuse.get("country"))
        + theme.stat("ISP", abuse.get("isp"))
        + theme.stat("Usage", abuse.get("usage"))
    )
    if abuse.get("link"):
        body += f"<div style='margin-top:10px'><a href='{theme.esc(abuse['link'])}' target='_blank'>Open in AbuseIPDB ↗</a></div>"
    return theme.card(title, body)


def _shodan_card(sh: dict | None) -> str:
    title = "🛰️ Shodan"
    if not sh:
        return theme.card(title, "<div class='ti-sub'>Only used for public IP addresses.</div>")
    if not sh.get("ok"):
        return theme.card(title, f"<div class='ti-sub ti-warn'>{theme.esc(sh.get('error'))}</div>")
    if not sh.get("found"):
        return theme.card(title, "<div class='ti-sub'>Shodan has no data for this host.</div>")
    ports = "".join(f"<span class='ti-chip ti-mono'>{p}</span>" for p in sh.get("ports", [])) or "<span class='ti-sub'>none seen</span>"
    body = (
        f"<div class='ti-sub' style='margin-bottom:4px'>Open ports</div><div style='margin-bottom:10px'>{ports}</div>"
        + theme.stat("Organisation", sh.get("org"))
        + theme.stat("OS", sh.get("os"))
        + theme.stat("Country", sh.get("country"))
        + theme.stat("Hostnames", ", ".join(sh.get("hostnames", [])[:3]))
        + theme.stat("Known CVEs", len(sh.get("vulns", [])))
    )
    if sh.get("link"):
        body += f"<div style='margin-top:10px'><a href='{theme.esc(sh['link'])}' target='_blank'>Open in Shodan ↗</a></div>"
    return theme.card(title, body)


def render_result(result: dict) -> None:
    risk = result.get("risk", "Unknown")
    reasons = "".join(f"<li>{theme.esc(r)}</li>" for r in result.get("reasons", []))
    notes = "".join(f"<li>{theme.esc(n)}</li>" for n in result.get("notes", []))
    errors = "".join(f"<li class='ti-warn'>{theme.esc(e)}</li>" for e in result.get("errors", []) + result.get("skipped", []))
    shown_input = result.get("input") if result.get("input") and result.get("input") != result.get("ioc") else ""
    refanged = f" · input <span class='ti-mono'>{theme.esc(shown_input)}</span>" if shown_input else ""
    st.markdown(
        "<div class='ti-card'><div class='ti-verdict'>"
        f"{theme.ring(risk)}<div style='flex:1;min-width:240px'>"
        f"<div class='ti-ioc ti-mono'>{theme.esc(result.get('ioc'))}</div>"
        f"<div class='ti-meta'>{theme.esc(result.get('type'))} · scanned {theme.esc(str(result.get('timestamp', '')).replace('T', ' '))}{refanged}</div>"
        f"</div></div><ul class='ti-reasons'>{reasons}{notes}{errors}</ul></div>",
        unsafe_allow_html=True,
    )
    st.write("")
    c1, c2, c3 = st.columns(3)
    c1.markdown(_vt_card(result.get("vt")), unsafe_allow_html=True)
    c2.markdown(_abuse_card(result.get("abuse")), unsafe_allow_html=True)
    c3.markdown(_shodan_card(result.get("shodan")), unsafe_allow_html=True)

    detections = (result.get("vt") or {}).get("detections") or []
    if detections:
        with st.expander(f"Engine detections ({len(detections)})"):
            st.dataframe(
                pd.DataFrame(detections).rename(columns={"engine": "Engine", "category": "Category", "result": "Verdict"}),
                hide_index=True, use_container_width=True,
            )
    with st.expander("Raw source data"):
        tabs = st.tabs(["VirusTotal", "AbuseIPDB", "Shodan"])
        for tab, field in zip(tabs, ("vt", "abuse", "shodan")):
            with tab:
                st.json(result.get(field) or {"note": "not queried"}, expanded=False)
