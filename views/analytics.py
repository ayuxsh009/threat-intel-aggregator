from datetime import date, datetime, timedelta

import streamlit as st

from tia import charts
from tia.config import RISK_COLORS
from tia.scanner import to_frame
from tia.ui import theme
from tia.ui.common import display_frame, get_store, history_scope, show_table

store = get_store()
theme.page_header("Overview", "Analytics", "Trends across scans: what is flagged, when, and how often.", as_of=f"Data as of {datetime.now():%Y-%m-%d %H:%M}")

scans = store.scans(history_scope())
if not scans:
    theme.empty_state("No data yet", "Charts appear once indicators have been scanned.")
    st.stop()

df_all = to_frame(scans)
first = df_all["timestamp"].min().date()
c1, _ = st.columns([1.3, 3])
period = c1.date_input("Period", value=(max(first, date.today() - timedelta(days=30)), date.today()),
                       min_value=first, max_value=date.today(), format="YYYY-MM-DD")
start, end = (period if isinstance(period, tuple) and len(period) == 2 else (first, date.today()))
mask = (df_all["timestamp"].dt.date >= start) & (df_all["timestamp"].dt.date <= end)
df = df_all[mask]
in_range = [s for s, keep in zip(scans, mask) if keep]

if df.empty:
    st.info("No scans in this period.")
    st.stop()

counts = df["risk"].value_counts().to_dict()
flagged = counts.get("High", 0) + counts.get("Medium", 0)
theme.kpi_row([
    ("Indicators", len(df), None, f"{df['ioc'].nunique()} unique"),
    ("Flagged", flagged, RISK_COLORS["High"], f"{flagged / len(df):.0%} high or medium"),
    ("IP addresses", int((df["type"] == "IP").sum()), None, f"{int((df['type'] == 'Domain').sum())} domains"),
    ("Lookup errors", int((df["issues"] != "").sum()), RISK_COLORS["Unknown"], "rate limits, bad keys"),
])
st.write("")

a, b = st.columns([1, 1.6])
with a, st.container(border=True):
    st.markdown("**Severity distribution**")
    st.plotly_chart(charts.risk_donut(counts), use_container_width=True, config={"displayModeBar": False})
with b, st.container(border=True):
    st.markdown("**Daily volume by severity**")
    st.plotly_chart(charts.activity_timeline(df), use_container_width=True, config={"displayModeBar": False})

a, b = st.columns([1.6, 1])
with a, st.container(border=True):
    st.markdown("**Top detected indicators** · VirusTotal")
    st.plotly_chart(charts.top_flagged(df), use_container_width=True, config={"displayModeBar": False})
with b, st.container(border=True):
    st.markdown("**Indicator types**")
    st.plotly_chart(charts.type_breakdown(df), use_container_width=True, config={"displayModeBar": False})

st.markdown("**High and medium severity in period**")
hot = [s for s in in_range if s.get("risk") in ("High", "Medium")]
if hot:
    show_table(display_frame(list(reversed(hot))))
else:
    st.caption("No high or medium severity indicators in this period.")
