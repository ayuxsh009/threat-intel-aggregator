"""Shared state, data access and result rendering for the Streamlit pages."""

from __future__ import annotations

import hashlib
from datetime import datetime

import pandas as pd
import streamlit as st

from tia import config, keys
from tia.keys import KEY_FIELDS  # noqa: F401  (re-exported for the pages)
from tia.config import RISK_COLORS
from tia.legacy import import_legacy_files
from tia.scanner import SOURCE_NAMES, to_frame
from tia.storage import Store
from tia.threatscore import RISKY_PORTS, band
from tia.ui import theme

SOURCE_FIELDS = ("vt", "abuse", "shodan", "threatfox", "urlhaus", "rdap")


PAGE_SCAN = "views/scan.py"
PAGE_INVESTIGATIONS = "views/investigations.py"
PAGE_REPORTS = "views/reports.py"
PAGE_SETTINGS = "views/settings.py"
PAGE_GRAPH = "views/graph.py"
PAGE_VERDICTS = "views/verdicts.py"


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
    return keys.resolve(store, _secrets_section("apikeys"))


def extension_token(store: Store) -> tuple[str, str]:
    return keys.api_token(store, {"api": _secrets_section("api")})


def api_keys(store: Store) -> dict[str, str]:
    return {k: v for k, (v, _) in resolve_keys(store).items()}


def source_status(store: Store) -> None:
    parts = []
    for key, (value, origin) in resolve_keys(store).items():
        label = KEY_FIELDS[key][0]
        color, state = ("#3fb950", "connected") if value else ("#6e7681", "not configured")
        parts.append(f"<span><span class='ti-dot' style='background:{color}'></span>{label} <span style='color:#6e7681'>· {state}</span></span>")
    parts.append("<span><span class='ti-dot' style='background:#3fb950'></span>RDAP <span style='color:#6e7681'>· no key needed</span></span>")
    st.markdown(f"<div class='ti-source-row'>{''.join(parts)}</div>", unsafe_allow_html=True)


# -- tables ---------------------------------------------------------------
def display_frame(results: list[dict]) -> pd.DataFrame:
    df = to_frame(results)
    if df.empty:
        return df
    return pd.DataFrame(
        {
            "Severity": df["risk"],
            "Score": pd.to_numeric(df["score"], errors="coerce"),
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
    "Score": st.column_config.ProgressColumn("Score", help="Explainable threat score, 0-100", min_value=0,
                                             max_value=100, format="%d", width="small"),
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


def score_color(points) -> str:
    if not isinstance(points, int):
        return RISK_COLORS["Unknown"]
    return RISK_COLORS[band(points)]


def _link(url: str | None, label: str) -> str:
    return f"<div class='ti-link'><a href='{theme.esc(url)}' target='_blank'>{label} ↗</a></div>" if url else ""


def _problem(name: str, result: dict) -> str:
    tag = "skipped" if result.get("skipped") else "error"
    return theme.card(name, f"<div class='ti-sub' style='color:#d29922'>{theme.esc(result.get('error'))}</div>", tag)


def _chips(values, mono: bool = False) -> str:
    cls = "ti-chip ti-mono" if mono else "ti-chip"
    return "".join(f"<span class='{cls}'>{theme.esc(v)}</span>" for v in values)


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
        body += f"<div style='margin-top:8px'>{_chips(vt['tags'][:8])}</div>"
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
    ports = sh.get("ports", [])
    port_chips = "".join(
        f"<span class='ti-chip ti-mono ti-chip-risk' title='{RISKY_PORTS[p]}'>{p}</span>" if p in RISKY_PORTS
        else f"<span class='ti-chip ti-mono'>{p}</span>"
        for p in ports
    ) or "<span class='ti-sub'>None observed</span>"
    vulns = sh.get("vulns", [])
    body = (
        f"<div class='ti-sub' style='margin-bottom:4px'>Open ports ({len(ports)})</div>"
        f"<div style='margin-bottom:8px'>{port_chips}</div>"
        + theme.stat("Organisation", sh.get("org"))
        + theme.stat("ISP", sh.get("isp"))
        + theme.stat("Operating system", sh.get("os"))
        + theme.stat("Country", sh.get("country"))
        + theme.stat("Hostnames", ", ".join(sh.get("hostnames", [])[:3]))
        + theme.stat("Known CVEs", len(vulns))
        + theme.stat("Last scanned", (sh.get("last_update") or "")[:10])
    )
    if vulns:
        body += f"<div style='margin-top:6px'>{_chips(vulns[:6], mono=True)}</div>"
    body += _link(sh.get("link"), "View on Shodan")
    return theme.card("Shodan", body, "host API")


def _factors_card(result: dict) -> str:
    factors = result.get("factors")
    points = result.get("score")
    if factors is None:
        return theme.card("Threat score", "<div class='ti-sub'>Scanned before scoring was added.</div>", "n/a")
    color = score_color(points)
    rows = "".join(
        "<div class='ti-factor'>"
        f"<span class='ti-factor-pts' style='color:{RISK_COLORS['Legitimate'] if f['points'] < 0 else color}'>"
        f"{f['points']:+d}</span><span class='ti-factor-label'>{theme.esc(f['label'])}"
        f"<span class='ti-factor-src'>{theme.esc(f['source'])}</span></span></div>"
        for f in factors
    ) or "<div class='ti-sub'>No risk factors found.</div>"
    body = (
        f"<div><span class='ti-big' style='color:{color}'>{points}</span>"
        f"<span class='ti-sub'> / 100 · {theme.esc(band(points))} band</span></div>"
        + theme.bar(points / 100, color) + rows
    )
    return theme.card("Why this score", body, "explainable")


def _feeds_card(result: dict) -> str:
    tf, uh = result.get("threatfox"), result.get("urlhaus")
    if not tf and not uh:
        return theme.card("Threat feeds", "<div class='ti-sub'>Add a free abuse.ch key in Settings to check "
                          "ThreatFox and URLhaus.</div>", "abuse.ch")
    body = ""
    if tf and not tf.get("ok"):
        body += f"<div class='ti-sub' style='color:#d29922'>{theme.esc(tf.get('error'))}</div>"
    elif tf:
        if tf.get("found"):
            body += ("<div class='ti-feed-hit'>ThreatFox match</div>"
                     + theme.stat("Malware family", ", ".join(tf.get("families") or []) or "unknown")
                     + theme.stat("Threat type", ", ".join(tf.get("threat_types") or []))
                     + theme.stat("Confidence", f"{tf.get('confidence', 0)}%")
                     + theme.stat("First seen", (tf.get("first_seen") or "")[:10]))
            body += _link(tf.get("link"), "View on ThreatFox")
        else:
            body += theme.stat("ThreatFox", "Not listed")
    if uh and not uh.get("ok"):
        body += f"<div class='ti-sub' style='color:#d29922'>{theme.esc(uh.get('error'))}</div>"
    elif uh:
        if uh.get("found"):
            body += ("<div class='ti-feed-hit' style='margin-top:8px'>URLhaus listing</div>"
                     + theme.stat("Malicious URLs", uh.get("count"))
                     + theme.stat("Online now", uh.get("online"))
                     + theme.stat("Threat", ", ".join(uh.get("threats") or []))
                     + theme.stat("First seen", (uh.get("first_seen") or "")[:10]))
            body += _link(uh.get("link"), "View on URLhaus")
        else:
            body += theme.stat("URLhaus", "Not listed" if not uh.get("note") else uh["note"])
    return theme.card("Threat feeds", body, "abuse.ch")


def _context_card(result: dict) -> str:
    body = ""
    rdap = result.get("rdap")
    if rdap:
        if not rdap.get("ok"):
            body += f"<div class='ti-sub' style='color:#d29922'>{theme.esc(rdap.get('error'))}</div>"
        elif rdap.get("found"):
            age = rdap.get("age_days")
            age_txt = f"{age} days" if age is not None else None
            age_color = RISK_COLORS["High"] if age is not None and age < 30 else (
                RISK_COLORS["Medium"] if age is not None and age < 180 else None)
            age_html = (f"<span style='color:{age_color};font-weight:600'>{age_txt}</span>"
                        if age_color else theme.esc(age_txt or "—"))
            body += ("<div class='ti-section'>Domain registration</div>"
                     + theme.stat("Domain", rdap.get("domain"))
                     + f"<div class='ti-stat'><span>Age</span><span>{age_html}</span></div>"
                     + theme.stat("Registered", rdap.get("registered"))
                     + theme.stat("Registrar", rdap.get("registrar"))
                     + theme.stat("Expires", rdap.get("expires")))
        else:
            body += "<div class='ti-section'>Domain registration</div>" + theme.stat("RDAP", "No record")

    seen = result.get("sightings") or {}
    body += "<div class='ti-section'>Seen in this workspace</div>"
    if seen.get("count"):
        body += (theme.stat("Earlier scans", seen["count"])
                 + theme.stat("Investigations", seen.get("investigations"))
                 + theme.stat("First seen", str(seen.get("first_seen") or "").replace("T", " ")[:16])
                 + theme.stat("Last seen", str(seen.get("last_seen") or "").replace("T", " ")[:16])
                 + theme.stat("Previous severity", seen.get("last_risk"))
                 + theme.stat("Worst severity", seen.get("worst_risk")))
    elif "sightings" in result:
        body += "<div class='ti-sub'>First time this indicator has been seen here.</div>"
    else:
        body += "<div class='ti-sub'>Not recorded for this scan.</div>"
    return theme.card("Context", body, "local intel")


def _verdict_control(result: dict, key: str) -> None:
    ioc = result.get("ioc")
    if not ioc:
        return
    store = get_store()
    current = store.get_verdict(ioc)
    options = ["No verdict", "Confirmed malicious", "False positive (benign)"]
    to_value = {options[1]: "malicious", options[2]: "benign"}
    index = {"malicious": 1, "benign": 2}.get((current or {}).get("verdict"), 0)
    label = "Analyst verdict"
    if current:
        label += f" · {options[index].split(' (')[0].lower()} by {current.get('username') or 'unknown'}"
    with st.expander(label, icon=":material/gavel:"):
        st.caption("Your decision overrides the computed score in every future scan of this indicator.")
        with st.form(f"verdict_{key}", border=False):
            choice = st.radio("Verdict", options, index=index, horizontal=True, label_visibility="collapsed")
            note = st.text_input("Note", value=(current or {}).get("note") or "",
                                 placeholder="Why? e.g. ticket number, sandbox result, owner confirmed")
            saved = st.form_submit_button("Save verdict", type="primary")
        if saved:
            if choice == options[0]:
                store.delete_verdict(ioc)
                st.toast("Verdict cleared", icon=":material/undo:")
            else:
                store.set_verdict(ioc, to_value[choice], ioc_type=result.get("type") or "", note=note,
                                  username=username())
                st.toast("Verdict saved", icon=":material/gavel:")
            st.rerun()


def render_result(result: dict, key: str = "") -> None:
    risk = result.get("risk", "Unknown")
    sources = [result.get(k) for k in SOURCE_FIELDS if result.get(k)]
    answered = sum(1 for s in sources if s.get("ok"))
    vt = result.get("vt") or {}
    detections = f"{vt.get('malicious', 0)}/{vt.get('total', 0)}" if vt.get("ok") and vt.get("found") else "—"
    points = result.get("score")

    items = "".join(f"<li>{theme.esc(r)}</li>" for r in result.get("reasons", []))
    items += "".join(f"<li class='ti-note'>{theme.esc(n)}</li>" for n in result.get("notes", []))
    items += "".join(f"<li class='ti-warn'>{theme.esc(e)}</li>" for e in result.get("errors", []) + result.get("skipped", []))
    shown_input = result.get("input") if result.get("input") and result.get("input") != result.get("ioc") else ""
    refanged = f"<span>Input <b class='ti-mono'>{theme.esc(shown_input)}</b></span>" if shown_input else ""
    verdict = result.get("verdict")
    badge = "<span class='ti-override'>Analyst override</span>" if verdict else ""
    score_html = (
        f"<div class='ti-score'><div class='n' style='color:{score_color(points)}'>{points}"
        f"<span class='of'>/100</span></div><div class='l'>Threat score</div></div>"
        if isinstance(points, int) else
        f"<div class='ti-score'><div class='n'>{detections}</div><div class='l'>VT detections</div></div>"
    )

    st.markdown(
        "<div class='ti-card'><div class='ti-verdict'><div>"
        f"{theme.severity(risk, large=True)}{badge}"
        f"<div class='ti-ioc ti-mono'>{theme.esc(result.get('ioc'))}</div>"
        "<div class='ti-meta'>"
        f"<span>Type <b>{theme.esc(result.get('type'))}</b></span>"
        f"<span>Scanned <b>{theme.esc(str(result.get('timestamp', '')).replace('T', ' '))}</b></span>"
        f"<span>Sources responded <b>{answered}/{len(sources)}</b></span>"
        f"<span>VT detections <b>{detections}</b></span>{refanged}"
        "</div></div>"
        f"{score_html}"
        f"</div><ul class='ti-reasons'>{items}</ul></div>",
        unsafe_allow_html=True,
    )
    changes = result.get("changes") or []
    if changes:
        st.markdown(
            "<div class='ti-changes'><b>Changed since the last scan</b><ul>"
            + "".join(f"<li>{theme.esc(c)}</li>" for c in changes) + "</ul></div>",
            unsafe_allow_html=True,
        )
    st.write("")
    c1, c2, c3 = st.columns(3)
    c1.markdown(_vt_card(result.get("vt")), unsafe_allow_html=True)
    c2.markdown(_abuse_card(result.get("abuse")), unsafe_allow_html=True)
    c3.markdown(_shodan_card(result.get("shodan")), unsafe_allow_html=True)
    st.write("")
    c1, c2, c3 = st.columns(3)
    c1.markdown(_factors_card(result), unsafe_allow_html=True)
    c2.markdown(_feeds_card(result), unsafe_allow_html=True)
    c3.markdown(_context_card(result), unsafe_allow_html=True)
    st.write("")

    widget_key = key or hashlib.sha1(f"{result.get('ioc')}|{result.get('timestamp')}".encode()).hexdigest()[:10]
    _verdict_control(result, widget_key)
    vendor_hits = vt.get("detections") or []
    if vendor_hits:
        with st.expander(f"Vendor detections ({len(vendor_hits)})"):
            st.dataframe(
                pd.DataFrame(vendor_hits).rename(columns={"engine": "Vendor", "category": "Category", "result": "Result"}),
                hide_index=True, use_container_width=True,
            )
    with st.expander("Raw API responses"):
        names = [SOURCE_NAMES[f] for f in SOURCE_FIELDS]
        for tab, field in zip(st.tabs(names), SOURCE_FIELDS):
            with tab:
                st.json(result.get(field) or {"note": "not queried"}, expanded=False)
