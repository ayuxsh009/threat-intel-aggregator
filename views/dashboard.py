from datetime import datetime, timedelta

import streamlit as st

from tia import charts
from tia.config import RISK_COLORS
from tia.scanner import to_frame
from tia.ui import theme
from tia.ui.common import (page_link, COLUMN_CONFIG, PAGE_INVESTIGATIONS, PAGE_SCAN, display_frame, get_store,
                           history_scope, username)

store = get_store()
hour = datetime.now().hour
greeting = "Good morning" if hour < 12 else "Good afternoon" if hour < 18 else "Good evening"
theme.page_header("Overview", f"{greeting}, {username()}", "Your threat-intelligence posture at a glance.")

scans = store.scans(history_scope())
if not scans:
    theme.empty_state("🛰️", "No scans yet", "Run your first lookup to populate the dashboard.")
    st.write("")
    _, c, _ = st.columns([2, 1, 2])
    page_link(c, PAGE_SCAN, "Start scanning", ":material/radar:")
    st.stop()

df = to_frame(scans)
counts = df["risk"].value_counts().to_dict()
week = df[df["timestamp"] >= datetime.now() - timedelta(days=7)]
theme.kpi_row([
    ("Scanned", len(df), "#6366f1", f"{len(week)} in the last 7 days"),
    ("High risk", counts.get("High", 0), RISK_COLORS["High"], "Act on these first"),
    ("Medium risk", counts.get("Medium", 0), RISK_COLORS["Medium"], "Worth a closer look"),
    ("Low risk", counts.get("Low", 0), RISK_COLORS["Low"], "Few detections"),
    ("Clean / unknown", counts.get("Legitimate", 0) + counts.get("Unknown", 0), RISK_COLORS["Legitimate"],
     f"{counts.get('Unknown', 0)} could not be checked"),
])
st.write("")

left, right = st.columns([1, 1.6])
with left:
    with st.container(border=True):
        st.markdown("**Risk distribution**")
        st.plotly_chart(charts.risk_donut(counts), use_container_width=True, config={"displayModeBar": False})
with right:
    with st.container(border=True):
        st.markdown("**Scan activity**")
        st.plotly_chart(charts.activity_timeline(df), use_container_width=True, config={"displayModeBar": False})

head, link = st.columns([4, 1])
head.markdown("#### Latest indicators")
page_link(link, PAGE_INVESTIGATIONS, "All investigations", ":material/arrow_forward:")
latest = list(reversed(scans))[:8]
st.dataframe(display_frame(latest).drop(columns=["Issues", "Open ports"]), hide_index=True,
             use_container_width=True, column_config=COLUMN_CONFIG)
