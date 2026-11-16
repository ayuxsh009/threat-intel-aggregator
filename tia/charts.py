"""Plotly figures with one consistent look for the app and the PDF."""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go

from .config import RISK_COLORS, RISK_ORDER

FONT = "Inter, 'Segoe UI', system-ui, sans-serif"


def _style(fig: go.Figure, *, height: int, print_mode: bool = False, legend: bool = True) -> go.Figure:
    text = "#0f172a" if print_mode else "#8b949e"
    grid = "#e2e8f0" if print_mode else "#21262d"
    bg = "white" if print_mode else "rgba(0,0,0,0)"
    fig.update_layout(
        height=height,
        margin=dict(l=8, r=8, t=36 if legend else 8, b=8),
        paper_bgcolor=bg,
        plot_bgcolor=bg,
        font=dict(family=FONT, color=text, size=12),
        showlegend=legend,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="left", x=0, title=None, traceorder="normal"),
        hoverlabel=dict(font_family=FONT),
    )
    fig.update_xaxes(gridcolor=grid, zeroline=False, linecolor=grid)
    fig.update_yaxes(gridcolor=grid, zeroline=False, linecolor=grid)
    return fig


def _empty(message: str, height: int) -> go.Figure:
    fig = go.Figure()
    fig.add_annotation(text=message, showarrow=False, font=dict(size=14, color="#64748b"))
    fig.update_xaxes(visible=False)
    fig.update_yaxes(visible=False)
    return _style(fig, height=height, legend=False)


def risk_donut(counts: dict, *, print_mode: bool = False, height: int = 320) -> go.Figure:
    labels = [r for r in RISK_ORDER if counts.get(r)]
    if not labels:
        return _empty("No scans yet", height)
    values = [int(counts[r]) for r in labels]
    fig = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.72,
            sort=False,
            direction="clockwise",
            marker=dict(colors=[RISK_COLORS[r] for r in labels],
                        line=dict(color="white" if print_mode else "#161b22", width=2)),
            textinfo="none",
            hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
        )
    )
    fig.add_annotation(
        text=f"{sum(values)}<br><span style='font-size:12px;color:#8b949e'>indicators</span>",
        showarrow=False,
        font=dict(size=26, color="#0f172a" if print_mode else "#e6edf3", family=FONT),
    )
    return _style(fig, height=height, print_mode=print_mode)


def activity_timeline(df: pd.DataFrame, *, height: int = 320) -> go.Figure:
    if df.empty:
        return _empty("No activity yet", height)
    d = df.assign(day=pd.to_datetime(df["timestamp"]).dt.date)
    pivot = d.groupby(["day", "risk"]).size().unstack(fill_value=0)
    fig = go.Figure(
        [
            go.Bar(x=pivot.index, y=pivot[r], name=r, marker_color=RISK_COLORS[r],
                   hovertemplate=f"{r}: %{{y}}<extra></extra>")
            for r in RISK_ORDER if r in pivot.columns
        ]
    )
    fig.update_layout(barmode="stack", bargap=0.55, hovermode="x unified")
    fig.update_xaxes(type="date", tickformat="%b %d")
    return _style(fig, height=height)


def top_flagged(df: pd.DataFrame, *, n: int = 10, height: int = 360) -> go.Figure:
    d = df.dropna(subset=["vt_malicious"])
    d = d[d["vt_malicious"] > 0].sort_values("timestamp").drop_duplicates("ioc", keep="last")
    d = d.nlargest(n, "vt_malicious").iloc[::-1]
    if d.empty:
        return _empty("Nothing flagged by VirusTotal", height)
    labels = [s if len(s) <= 38 else s[:36] + "…" for s in d["ioc"].astype(str)]
    fig = go.Figure(
        go.Bar(
            x=d["vt_malicious"], y=labels, orientation="h",
            marker_color=[RISK_COLORS.get(r, "#2f81f7") for r in d["risk"]],
            text=d["vt_malicious"], textposition="outside", cliponaxis=False,
            customdata=d["ioc"], hovertemplate="%{customdata}<br>%{x} engines<extra></extra>",
        )
    )
    fig.update_xaxes(title_text="Engines flagging as malicious")
    return _style(fig, height=height, legend=False)


def type_breakdown(df: pd.DataFrame, *, height: int = 360) -> go.Figure:
    if df.empty:
        return _empty("No data", height)
    counts = df["type"].value_counts()
    fig = go.Figure(
        go.Bar(x=counts.index, y=counts.values, marker_color="#2f81f7",
               text=counts.values, textposition="outside", cliponaxis=False,
               hovertemplate="%{x}: %{y}<extra></extra>")
    )
    fig.update_layout(bargap=0.5)
    return _style(fig, height=height, legend=False)


def chart_png(fig: go.Figure, *, width: int = 900, height: int = 420) -> bytes | None:
    """Render a figure to PNG with Kaleido. Returns None if Kaleido/Chrome is unavailable."""
    try:
        return fig.to_image(format="png", width=width, height=height, scale=2)
    except Exception:
        return None
