from datetime import datetime, timedelta

import streamlit as st

from tia import charts
from tia.config import RISK_COLORS
from tia.scanner import to_frame
from tia.ui import theme
from tia.ui.common import (page_link, PAGE_INVESTIGATIONS, PAGE_SCAN, display_frame, get_store,
                           history_scope, show_table)

store = get_store()
theme.page_header("Overview", "Dashboard", "Summary of all indicators scanned in this workspace.",
                  as_of=f"Data as of {datetime.now():%Y-%m-%d %H:%M}")

scans = store.scans(history_scope())
if not scans:
    theme.empty_state("No scans yet", "Run a lookup on the Scan page to populate the dashboard.")
    st.write("")
    _, c, _ = st.columns([2, 1, 2])
    page_link(c, PAGE_SCAN, "Start scanning", ":material/radar:")
    st.stop()

df = to_frame(scans)
counts = df["risk"].value_counts().to_dict()
week = df[df["timestamp"] >= datetime.now() - timedelta(days=7)]
theme.kpi_row([
    ("Indicators scanned", len(df), None, f"{len(week)} in the last 7 days"),
    ("High", counts.get("High", 0), RISK_COLORS["High"], "Prioritise for response"),
    ("Medium", counts.get("Medium", 0), RISK_COLORS["Medium"], "Review recommended"),
    ("Low", counts.get("Low", 0), RISK_COLORS["Low"], "Limited detections"),
    ("No detections", counts.get("Legitimate", 0), RISK_COLORS["Legitimate"],
     f"{counts.get('Unknown', 0)} unknown (lookup failed)"),
])
st.write("")

left, right = st.columns([1, 1.6])
with left:
    with st.container(border=True):
        st.markdown("**Severity distribution**")
        st.plotly_chart(charts.risk_donut(counts), use_container_width=True, config={"displayModeBar": False})
with right:
    with st.container(border=True):
        st.markdown("**Scan volume by day**")
        st.plotly_chart(charts.activity_timeline(df), use_container_width=True, config={"displayModeBar": False})

head, link = st.columns([4, 1])
head.markdown("**Recent indicators**")
page_link(link, PAGE_INVESTIGATIONS, "All investigations", ":material/arrow_forward:")
latest = list(reversed(scans))[:8]
show_table(display_frame(latest).drop(columns=["Issues", "Open ports", "Country"]))
