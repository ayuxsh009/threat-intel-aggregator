from datetime import datetime

import streamlit as st

from tia.config import RISK_ORDER
from tia.ui import theme
from tia.ui.common import (page_link, PAGE_REPORTS, PAGE_SCAN, csv_bytes, display_frame, get_store,
                           history_scope, is_admin, render_result, session_picker, show_table, summary_pills)

store = get_store()
theme.page_header("Investigate", "Investigations",
                  "Every scan is saved as an investigation. Filter it, open any indicator, or turn it into a report.")

sid, sessions = session_picker(store, key="inv_session")
if not sid:
    theme.empty_state("No investigations", "Every scan you run is saved here as an investigation.")
    st.write("")
    _, c, _ = st.columns([2, 1, 2])
    page_link(c, PAGE_SCAN, "Start scanning", ":material/radar:")
    st.stop()

results = store.session_results(sid)
summary_pills(results)

f1, f2, f3 = st.columns([2.2, 1.6, 1.4])
present = [r for r in RISK_ORDER if any(x.get("risk") == r for x in results)]
risks = f1.pills("Severity", present, selection_mode="multi", default=present, key=f"risk_{sid}")
query = f2.text_input("Search", placeholder="Filter indicators…", key=f"q_{sid}")
types = sorted({r.get("type", "Unknown") for r in results})
type_sel = f3.multiselect("Type", types, default=types, key=f"type_{sid}")

filtered = [
    r for r in results
    if r.get("risk") in (risks or [])
    and r.get("type") in type_sel
    and (not query or query.lower() in str(r.get("ioc", "")).lower())
]

event = show_table(display_frame(filtered), on_select="rerun", selection_mode="single-row", key=f"table_{sid}")
st.caption(f"Showing {len(filtered)} of {len(results)} indicators · select a row for full details")

c1, c2, c3, c4 = st.columns(4)
c1.download_button("Download CSV", csv_bytes(filtered), f"investigation_{datetime.now():%Y%m%d_%H%M%S}.csv",
                   "text/csv", use_container_width=True, icon=":material/download:")
if c2.button("Build report", use_container_width=True, icon=":material/picture_as_pdf:"):
    st.switch_page(PAGE_REPORTS)


@st.dialog("Delete investigation")
def confirm_delete():
    st.write("This permanently removes this investigation and all its results.")
    if st.button("Delete", type="primary", icon=":material/delete:"):
        store.delete_session(sid)
        st.session_state.pop("selected_session", None)
        st.rerun()


@st.dialog("Clear history")
def confirm_clear():
    scope = "every user's" if is_admin() else "your"
    st.write(f"This permanently removes **all** of {scope} scan history.")
    if st.button("Clear everything", type="primary", icon=":material/delete_forever:"):
        store.clear_history(history_scope())
        st.session_state.pop("selected_session", None)
        st.rerun()


if c3.button("Delete investigation", use_container_width=True, icon=":material/delete:"):
    confirm_delete()
if c4.button("Clear all history", use_container_width=True, icon=":material/delete_sweep:"):
    confirm_clear()

rows = event.selection.rows if event and getattr(event, "selection", None) else []
if rows and rows[0] < len(filtered):
    st.divider()
    render_result(filtered[rows[0]])
