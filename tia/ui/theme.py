"""Visual theme: global CSS and small HTML components."""

from __future__ import annotations

import base64
import html
from functools import lru_cache

import streamlit as st

from tia.config import ASSETS_DIR, RISK_COLORS

_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');

:root {
  --ti-bg: #0b1020;
  --ti-panel: rgba(19, 27, 48, 0.78);
  --ti-border: rgba(148, 163, 184, 0.14);
  --ti-muted: #94a3b8;
  --ti-text: #e2e8f0;
  --ti-accent: #6366f1;
  --ti-accent-2: #22d3ee;
}
html, body, .stApp, [data-testid="stMarkdownContainer"], button, input, textarea, select {
  font-family: 'Inter', system-ui, -apple-system, 'Segoe UI', sans-serif !important;
}
code, pre, .ti-mono { font-family: 'JetBrains Mono', ui-monospace, monospace !important; }

.stApp {
  background:
    radial-gradient(1100px 520px at 0% -10%, rgba(99, 102, 241, 0.13), transparent 60%),
    radial-gradient(900px 480px at 100% 0%, rgba(34, 211, 238, 0.07), transparent 60%),
    var(--ti-bg);
}
[data-testid="stHeader"] { background: transparent; }
[data-testid="stDecoration"] { display: none; }
.block-container { padding-top: 2.2rem; padding-bottom: 4rem; max-width: 1320px; }
[data-testid="stHeaderActionElements"] { display: none !important; }

/* Sidebar */
[data-testid="stSidebarHeader"] img, [data-testid="stLogo"] { height: 2.6rem !important; max-width: 13rem; }
[data-testid="stSidebar"] {
  background: linear-gradient(180deg, #0d1428 0%, #0a1020 100%);
  border-right: 1px solid var(--ti-border);
}
[data-testid="stSidebarNavSeparator"] { border-color: var(--ti-border); }
[data-testid="stSidebarNav"] a { border-radius: 10px; margin: 1px 0; }
[data-testid="stSidebarNav"] a[aria-current="page"] {
  background: rgba(99, 102, 241, 0.16);
}
[data-testid="stNavSectionHeader"] {
  text-transform: uppercase; letter-spacing: .1em; font-size: .68rem !important; color: #64748b !important;
}

/* Buttons */
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button {
  border-radius: 10px; font-weight: 600; border: 1px solid var(--ti-border);
  transition: transform .08s ease, box-shadow .15s ease, background .15s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover {
  border-color: rgba(129, 140, 248, .55);
}
button[kind="primary"], button[kind="primaryFormSubmit"],
button[data-testid="stBaseButton-primary"], button[data-testid="stBaseButton-primaryFormSubmit"] {
  background: linear-gradient(135deg, #6366f1 0%, #4f46e5 55%, #0891b2 140%) !important;
  border: none !important; color: #fff !important;
  box-shadow: 0 6px 18px -6px rgba(99, 102, 241, .65);
}
button[kind="primary"]:hover, button[data-testid="stBaseButton-primary"]:hover,
button[data-testid="stBaseButton-primaryFormSubmit"]:hover { transform: translateY(-1px); }

/* Inputs */
[data-baseweb="input"], [data-baseweb="select"] > div, [data-baseweb="textarea"] {
  border-radius: 10px !important;
}
[data-testid="stForm"], [data-testid="stVerticalBlockBorderWrapper"]:has(> div > [data-testid="stVerticalBlock"]) {
  border-radius: 16px;
}
[data-testid="stForm"] { background: var(--ti-panel); border: 1px solid var(--ti-border); }

/* Tabs */
.stTabs [data-baseweb="tab-list"] { gap: 4px; border-bottom: 1px solid var(--ti-border); }
.stTabs [data-baseweb="tab"] { padding: 10px 16px; font-weight: 600; }
.stTabs [data-baseweb="tab-highlight"] { background: linear-gradient(90deg, var(--ti-accent), var(--ti-accent-2)); }

/* Dataframes & expanders */
[data-testid="stDataFrame"] { border: 1px solid var(--ti-border); border-radius: 12px; overflow: hidden; }
[data-testid="stExpander"] details { border-radius: 12px; border-color: var(--ti-border); background: rgba(15,22,40,.5); }

/* Custom components */
.ti-header { margin-bottom: 1.4rem; }
.ti-eyebrow { color: #818cf8; font-size: .74rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
.ti-header h1 { font-size: 2rem; font-weight: 800; letter-spacing: -.025em; margin: .15rem 0 .25rem; padding: 0; color: #f8fafc; }
.ti-header p { color: var(--ti-muted); margin: 0; font-size: .98rem; max-width: 760px; }

.ti-card {
  background: var(--ti-panel); border: 1px solid var(--ti-border); border-radius: 16px;
  padding: 18px 20px; backdrop-filter: blur(6px); height: 100%;
}
.ti-card h4 { margin: 0 0 10px; font-size: .95rem; font-weight: 700; color: #f1f5f9; display:flex; align-items:center; gap:8px; }
.ti-card .ti-sub { color: var(--ti-muted); font-size: .82rem; }

.ti-kpi { position: relative; overflow: hidden; padding: 16px 18px 14px; min-height: 124px; }
.ti-kpi::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 3px; background: var(--kpi, #6366f1); }
.ti-kpi::after {
  content: ""; position: absolute; right: -30px; top: -30px; width: 110px; height: 110px; border-radius: 50%;
  background: radial-gradient(circle, color-mix(in srgb, var(--kpi, #6366f1) 22%, transparent), transparent 70%);
}
.ti-kpi .ti-label { color: var(--ti-muted); font-size: .72rem; font-weight: 700; letter-spacing: .1em; text-transform: uppercase; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ti-kpi .ti-value { font-size: 2.05rem; font-weight: 800; color: #f8fafc; line-height: 1.15; margin-top: 6px; letter-spacing: -.02em; }
.ti-kpi .ti-hint { color: var(--ti-muted); font-size: .8rem; margin-top: 2px; }

.ti-pill {
  display: inline-flex; align-items: center; gap: 7px; padding: 3px 11px 3px 9px; border-radius: 999px;
  font-size: .78rem; font-weight: 700; letter-spacing: .02em; white-space: nowrap;
}
.ti-pill .dot { width: 7px; height: 7px; border-radius: 50%; }
.ti-chip {
  display: inline-block; padding: 2px 9px; margin: 2px 4px 2px 0; border-radius: 7px; font-size: .78rem;
  background: rgba(148,163,184,.1); border: 1px solid var(--ti-border); color: #cbd5e1;
}

.ti-verdict { display: flex; gap: 18px; align-items: center; flex-wrap: wrap; }
.ti-verdict .ti-ioc { font-size: 1.25rem; font-weight: 700; color: #f8fafc; word-break: break-all; }
.ti-verdict .ti-meta { color: var(--ti-muted); font-size: .86rem; margin-top: 2px; }
.ti-ring {
  width: 74px; height: 74px; border-radius: 50%; display: grid; place-items: center; flex-shrink: 0;
  font-weight: 800; font-size: .8rem; letter-spacing: .05em; text-transform: uppercase;
}
.ti-reasons { margin: 12px 0 0; padding-left: 18px; color: #cbd5e1; font-size: .9rem; }
.ti-reasons li { margin: 3px 0; }
.ti-warn { color: #fbbf24; }

.ti-stat { display: flex; justify-content: space-between; padding: 7px 0; border-bottom: 1px dashed var(--ti-border); font-size: .88rem; }
.ti-stat:last-child { border-bottom: none; }
.ti-stat span:first-child { color: var(--ti-muted); }
.ti-stat span:last-child { color: #f1f5f9; font-weight: 600; text-align: right; }
.ti-bar { height: 8px; border-radius: 99px; background: rgba(148,163,184,.14); overflow: hidden; margin: 6px 0 12px; }
.ti-bar > div { height: 100%; border-radius: 99px; }

.ti-source-row { display: flex; gap: 8px; flex-wrap: wrap; margin: -.4rem 0 1rem; }
.ti-source { font-size: .78rem; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--ti-border); color: #cbd5e1; }
.ti-source b { font-weight: 700; }

.ti-brand { display: flex; align-items: center; gap: 10px; }
.ti-brand .name { font-weight: 800; font-size: 1.02rem; color: #f8fafc; letter-spacing: -.01em; line-height: 1.1; }
.ti-brand .tag { color: #64748b; font-size: .72rem; font-weight: 600; letter-spacing: .06em; text-transform: uppercase; }

.ti-user { display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:12px; background: rgba(148,163,184,.07); border:1px solid var(--ti-border); margin-bottom: 8px; }
.ti-avatar { width: 32px; height: 32px; border-radius: 50%; display:grid; place-items:center; font-weight:800; color:white;
  background: linear-gradient(135deg, #6366f1, #22d3ee); font-size: .85rem; }
.ti-user .who { font-weight: 700; color: #f1f5f9; font-size: .88rem; }
.ti-user .role { color: #94a3b8; font-size: .72rem; text-transform: uppercase; letter-spacing: .08em; }

.ti-empty { text-align: center; padding: 48px 20px; }
.ti-empty .icon { font-size: 2.4rem; }
.ti-empty h3 { margin: .4rem 0 .2rem; color: #f1f5f9; }
.ti-empty p { color: var(--ti-muted); margin: 0; }

.ti-login-hero { text-align: center; margin: 5vh 0 1.4rem; }
.ti-login-hero h1 { font-size: 1.9rem; font-weight: 800; letter-spacing: -.03em; margin: .7rem 0 .2rem; color:#f8fafc; padding:0; }
.ti-login-hero p { color: var(--ti-muted); margin: 0; }
.ti-foot { text-align:center; color:#475569; font-size:.78rem; margin-top: 1.2rem; }
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


def page_header(eyebrow: str, title: str, subtitle: str = "") -> None:
    sub = f"<p>{esc(subtitle)}</p>" if subtitle else ""
    st.markdown(
        f"<div class='ti-header'><div class='ti-eyebrow'>{esc(eyebrow)}</div>"
        f"<h1>{esc(title)}</h1>{sub}</div>",
        unsafe_allow_html=True,
    )


def risk_pill(risk: str) -> str:
    c = RISK_COLORS.get(risk, RISK_COLORS["Unknown"])
    return (
        f"<span class='ti-pill' style='background:{_rgba(c, .14)};color:{c};border:1px solid {_rgba(c, .35)}'>"
        f"<span class='dot' style='background:{c}'></span>{esc(risk)}</span>"
    )


def kpi(label: str, value, color: str = "#6366f1", hint: str = "") -> str:
    h = f"<div class='ti-hint'>{esc(hint)}</div>" if hint else ""
    return (
        f"<div class='ti-card ti-kpi' style='--kpi:{color}'><div class='ti-label'>{esc(label)}</div>"
        f"<div class='ti-value'>{esc(value)}</div>{h}</div>"
    )


def kpi_row(items: list[tuple]) -> None:
    cols = st.columns(len(items))
    for col, item in zip(cols, items):
        col.markdown(kpi(*item), unsafe_allow_html=True)


def ring(risk: str) -> str:
    c = RISK_COLORS.get(risk, RISK_COLORS["Unknown"])
    return (
        f"<div class='ti-ring' style='background:radial-gradient(circle, {_rgba(c, .22)} 0%, {_rgba(c, .06)} 70%);"
        f"border:2px solid {c};color:{c};box-shadow:0 0 28px -6px {_rgba(c, .7)}'>{esc(risk)}</div>"
    )


def bar(fraction: float, color: str) -> str:
    pct = max(0.0, min(1.0, fraction)) * 100
    return f"<div class='ti-bar'><div style='width:{pct:.1f}%;background:{color}'></div></div>"


def stat(label: str, value) -> str:
    return f"<div class='ti-stat'><span>{esc(label)}</span><span>{esc(value if value not in (None, '') else '-')}</span></div>"


def card(title: str, body_html: str) -> str:
    return f"<div class='ti-card'><h4>{title}</h4>{body_html}</div>"


def empty_state(icon: str, title: str, text: str) -> None:
    st.markdown(
        f"<div class='ti-card ti-empty'><div class='icon'>{icon}</div><h3>{esc(title)}</h3><p>{esc(text)}</p></div>",
        unsafe_allow_html=True,
    )
