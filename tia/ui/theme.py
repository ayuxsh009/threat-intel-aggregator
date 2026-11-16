"""Visual theme: global CSS and small HTML components.

The look follows established security tooling: flat neutral surfaces,
1px borders, compact type, and colour reserved for severity.
"""

from __future__ import annotations

import base64
import html
from functools import lru_cache

import streamlit as st

from tia.config import ASSETS_DIR, RISK_COLORS

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --bg: #0d1117;
  --surface: #161b22;
  --surface-2: #1c2129;
  --border: #30363d;
  --border-muted: #21262d;
  --text: #e6edf3;
  --text-muted: #8b949e;
  --text-subtle: #6e7681;
  --accent: #2f81f7;
}
html, body, .stApp, [data-testid="stMarkdownContainer"], button, input, textarea, select {
  font-family: 'Inter', -apple-system, 'Segoe UI', sans-serif !important;
}
code, pre, .ti-mono { font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, Consolas, monospace !important; }
.stApp { background: var(--bg); }
[data-testid="stHeader"] { background: transparent; }
[data-testid="stDecoration"] { display: none; }
.block-container { padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1400px; }
[data-testid="stHeaderActionElements"] { display: none !important; }
p, li { font-size: .92rem; }

/* Sidebar */
[data-testid="stSidebar"] { background: #010409; border-right: 1px solid var(--border-muted); }
[data-testid="stSidebarHeader"] img, [data-testid="stLogo"] { height: 2.3rem !important; max-width: 12rem; }
[data-testid="stSidebarNav"] a { border-radius: 6px; margin: 0; padding-top: .2rem; padding-bottom: .2rem; }
[data-testid="stSidebarNav"] a span { font-size: .88rem; }
[data-testid="stSidebarNav"] a[aria-current="page"] { background: var(--surface-2); }
[data-testid="stSidebarNav"] a[aria-current="page"] span { color: var(--text) !important; font-weight: 600; }
[data-testid="stNavSectionHeader"] {
  text-transform: uppercase; letter-spacing: .06em; font-size: .68rem !important; color: var(--text-subtle) !important; font-weight: 600;
}

/* Buttons: flat, small radius */
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {
  border-radius: 6px; font-weight: 500; font-size: .88rem; border: 1px solid var(--border);
  background: #21262d; color: var(--text); min-height: 2.2rem;
}
.stButton > button:hover, .stDownloadButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover {
  background: #30363d; border-color: #8b949e; color: var(--text);
}
button[kind="primary"], button[kind="primaryFormSubmit"],
button[data-testid="stBaseButton-primary"], button[data-testid="stBaseButton-primaryFormSubmit"] {
  background: #238636 !important; border: 1px solid rgba(240,246,252,.1) !important; color: #fff !important;
}
button[kind="primary"]:hover, button[data-testid="stBaseButton-primary"]:hover,
button[data-testid="stBaseButton-primaryFormSubmit"]:hover { background: #2ea043 !important; }

/* Inputs, forms, containers */
[data-baseweb="input"], [data-baseweb="select"] > div, [data-baseweb="textarea"] { border-radius: 6px !important; }
[data-testid="stForm"] { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; }
[data-testid="stVerticalBlockBorderWrapper"] { border-radius: 8px; }
label p { font-size: .85rem !important; color: var(--text-muted) !important; }

/* Tabs */
.stTabs [data-baseweb="tab-list"] { gap: 0; border-bottom: 1px solid var(--border-muted); }
.stTabs [data-baseweb="tab"] { padding: 8px 16px; font-size: .88rem; }
.stTabs [data-baseweb="tab-highlight"] { background: #f78166; height: 2px; }

/* Tables & expanders */
[data-testid="stDataFrame"] { border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }
[data-testid="stExpander"] details { border-radius: 6px; border-color: var(--border); background: var(--surface); }
[data-testid="stExpander"] summary p { font-size: .88rem; font-weight: 500; }

/* Page header */
.ti-header { display: flex; justify-content: space-between; align-items: flex-end; gap: 16px;
  padding-bottom: 14px; margin-bottom: 18px; border-bottom: 1px solid var(--border-muted); flex-wrap: wrap; }
.ti-crumb { color: var(--text-subtle); font-size: .78rem; margin-bottom: 4px; }
.ti-crumb b { color: var(--text-muted); font-weight: 500; }
.ti-header h1 { font-size: 1.45rem; font-weight: 600; letter-spacing: -.01em; margin: 0; padding: 0; color: var(--text); }
.ti-header p { color: var(--text-muted); margin: 4px 0 0; font-size: .88rem; max-width: 780px; }
.ti-asof { color: var(--text-subtle); font-size: .78rem; white-space: nowrap; }

/* Panels */
.ti-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; height: 100%; }
.ti-card-title { display: flex; justify-content: space-between; align-items: center; margin: -2px 0 10px;
  padding-bottom: 10px; border-bottom: 1px solid var(--border-muted); }
.ti-card-title span:first-child { font-size: .85rem; font-weight: 600; color: var(--text); }
.ti-card-title span:last-child { font-size: .75rem; color: var(--text-subtle); }
.ti-sub { color: var(--text-muted); font-size: .84rem; }

/* KPI */
.ti-kpi .ti-label { color: var(--text-muted); font-size: .78rem; font-weight: 500; display: flex; align-items: center; gap: 6px; white-space: nowrap; }
.ti-kpi .ti-sq { width: 8px; height: 8px; border-radius: 2px; display: inline-block; }
.ti-kpi .ti-value { font-size: 1.65rem; font-weight: 600; color: var(--text); line-height: 1.2; margin-top: 6px; font-variant-numeric: tabular-nums; }
.ti-kpi .ti-hint { color: var(--text-subtle); font-size: .76rem; margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* Severity badge */
.ti-sev { display: inline-block; padding: 1px 7px; border-radius: 4px; font-size: .7rem; font-weight: 600;
  letter-spacing: .04em; text-transform: uppercase; border: 1px solid; line-height: 1.5; white-space: nowrap; }
.ti-sev-lg { font-size: .8rem; padding: 4px 10px; }
.ti-count { color: var(--text); font-weight: 600; font-size: .85rem; margin: 0 14px 0 6px; font-variant-numeric: tabular-nums; }

/* Verdict header */
.ti-verdict { display: grid; grid-template-columns: 1fr auto; gap: 16px; align-items: start; }
.ti-verdict .ti-ioc { font-size: 1.05rem; font-weight: 500; color: var(--text); word-break: break-all; margin: 8px 0 6px; }
.ti-meta { display: flex; gap: 18px; flex-wrap: wrap; color: var(--text-muted); font-size: .8rem; }
.ti-meta b { color: var(--text); font-weight: 500; }
.ti-reasons { margin: 12px 0 0; padding: 10px 0 0; border-top: 1px solid var(--border-muted); list-style: none; }
.ti-reasons li { font-size: .84rem; color: var(--text); margin: 3px 0; padding-left: 14px; position: relative; }
.ti-reasons li::before { content: ""; position: absolute; left: 0; top: .55em; width: 5px; height: 5px; border-radius: 1px; background: var(--text-subtle); }
.ti-reasons li.ti-warn { color: #d29922; }
.ti-reasons li.ti-warn::before { background: #d29922; }
.ti-reasons li.ti-note { color: var(--text-muted); }
.ti-score { text-align: right; }
.ti-score .n { font-size: 1.6rem; font-weight: 600; color: var(--text); font-variant-numeric: tabular-nums; }
.ti-score .l { font-size: .72rem; color: var(--text-subtle); text-transform: uppercase; letter-spacing: .05em; }

/* Key/value rows */
.ti-stat { display: flex; justify-content: space-between; gap: 12px; padding: 5px 0; font-size: .82rem; border-bottom: 1px solid var(--border-muted); }
.ti-stat:last-child { border-bottom: none; }
.ti-stat span:first-child { color: var(--text-muted); }
.ti-stat span:last-child { color: var(--text); text-align: right; font-variant-numeric: tabular-nums; }
.ti-bar { height: 6px; border-radius: 3px; background: var(--border-muted); overflow: hidden; margin: 6px 0 10px; }
.ti-bar > div { height: 100%; }
.ti-big { font-size: 1.35rem; font-weight: 600; font-variant-numeric: tabular-nums; }
.ti-chip { display: inline-block; padding: 0 6px; margin: 2px 4px 2px 0; border-radius: 4px; font-size: .76rem;
  background: var(--surface-2); border: 1px solid var(--border); color: var(--text); }
.ti-link { font-size: .8rem; margin-top: 10px; display: inline-block; }
.ti-link a { color: var(--accent) !important; text-decoration: none; }
.ti-link a:hover { text-decoration: underline; }

/* Source status strip */
.ti-source-row { display: flex; gap: 16px; flex-wrap: wrap; margin: 0 0 14px; font-size: .8rem; color: var(--text-muted); }
.ti-dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 6px; vertical-align: 1px; }

/* Sidebar user */
.ti-user { display: flex; align-items: center; gap: 10px; padding: 14px 4px 8px; margin-bottom: 6px; border-top: 1px solid var(--border-muted); }
.ti-avatar { width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center; font-weight: 600; font-size: .78rem;
  color: var(--text); background: var(--surface-2); border: 1px solid var(--border); }
.ti-user .who { font-weight: 600; color: var(--text); font-size: .85rem; line-height: 1.2; }
.ti-user .role { color: var(--text-subtle); font-size: .74rem; }

/* Empty state */
.ti-empty { text-align: center; padding: 40px 20px; border: 1px dashed var(--border); border-radius: 8px; }
.ti-empty h3 { margin: 0 0 4px; color: var(--text); font-size: 1rem; font-weight: 600; }
.ti-empty p { color: var(--text-muted); margin: 0; font-size: .86rem; }

/* Login */
.ti-login-hero { text-align: center; margin: 8vh 0 1.2rem; }
.ti-login-hero h1 { font-size: 1.35rem; font-weight: 600; margin: .9rem 0 .2rem; color: var(--text); padding: 0; }
.ti-login-hero p { color: var(--text-muted); margin: 0; font-size: .88rem; }
.ti-foot { text-align: center; color: var(--text-subtle); font-size: .75rem; margin-top: 1rem; }
</style>
"""


def inject_css() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)


def hide_sidebar() -> None:
    st.markdown(
        "<style>[data-testid='stSidebar'],[data-testid='stSidebarCollapsedControl'],"
        "[data-testid='collapsedControl']{display:none !important}</style>",
        unsafe_allow_html=True,
    )


@lru_cache(maxsize=1)
def logo_data_uri() -> str:
    svg = (ASSETS_DIR / "logo.svg").read_bytes()
    return "data:image/svg+xml;base64," + base64.b64encode(svg).decode()


def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def _rgba(hex_color: str, alpha: float) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def page_header(section: str, title: str, subtitle: str = "", as_of: str = "") -> None:
    sub = f"<p>{esc(subtitle)}</p>" if subtitle else ""
    right = f"<div class='ti-asof'>{esc(as_of)}</div>" if as_of else ""
    st.markdown(
        f"<div class='ti-header'><div><div class='ti-crumb'>Threat Intel / <b>{esc(section)}</b></div>"
        f"<h1>{esc(title)}</h1>{sub}</div>{right}</div>",
        unsafe_allow_html=True,
    )


def severity(risk: str, large: bool = False) -> str:
    c = RISK_COLORS.get(risk, RISK_COLORS["Unknown"])
    size = " ti-sev-lg" if large else ""
    return (f"<span class='ti-sev{size}' style='color:{c};background:{_rgba(c, .1)};"
            f"border-color:{_rgba(c, .4)}'>{esc(risk)}</span>")


def kpi(label: str, value, color: str | None = None, hint: str = "") -> str:
    sq = f"<span class='ti-sq' style='background:{color}'></span>" if color else ""
    h = f"<div class='ti-hint'>{esc(hint)}</div>" if hint else "<div class='ti-hint'>&nbsp;</div>"
    return (f"<div class='ti-card ti-kpi'><div class='ti-label'>{sq}{esc(label)}</div>"
            f"<div class='ti-value'>{esc(value)}</div>{h}</div>")


def kpi_row(items: list[tuple]) -> None:
    cols = st.columns(len(items))
    for col, item in zip(cols, items):
        col.markdown(kpi(*item), unsafe_allow_html=True)


def bar(fraction: float, color: str) -> str:
    pct = max(0.0, min(1.0, fraction)) * 100
    return f"<div class='ti-bar'><div style='width:{pct:.1f}%;background:{color}'></div></div>"


def stat(label: str, value) -> str:
    shown = value if value not in (None, "") else "—"
    return f"<div class='ti-stat'><span>{esc(label)}</span><span>{esc(shown)}</span></div>"


def card(title: str, body_html: str, tag: str = "") -> str:
    return (f"<div class='ti-card'><div class='ti-card-title'><span>{esc(title)}</span><span>{esc(tag)}</span></div>"
            f"{body_html}</div>")


def empty_state(title: str, text: str) -> None:
    st.markdown(f"<div class='ti-empty'><h3>{esc(title)}</h3><p>{esc(text)}</p></div>", unsafe_allow_html=True)
