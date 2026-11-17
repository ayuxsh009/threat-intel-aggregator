from datetime import datetime

import pandas as pd
import streamlit as st

from tia.ioc import normalize
from tia.ui import theme
from tia.ui.common import get_store, username

store = get_store()
theme.page_header("Investigate", "Verdicts",
                  "Analyst decisions that override computed results: your own allow list (false positives) "
                  "and block list (confirmed malicious). They apply to every future scan.")

verdicts = store.list_verdicts()
malicious = [v for v in verdicts if v["verdict"] == "malicious"]
benign = [v for v in verdicts if v["verdict"] == "benign"]
theme.kpi_row([
    ("Confirmed malicious", len(malicious), "#f85149", "block list"),
    ("False positives", len(benign), "#3fb950", "allow list"),
    ("Analysts", len({v["username"] for v in verdicts if v.get("username")}), None, "contributed verdicts"),
])
st.write("")

left, right = st.columns([1, 1.9])
with left, st.form("add_verdict", clear_on_submit=True):
    st.markdown("**Add or update a verdict**")
    raw = st.text_input("Indicator", placeholder="IP, domain, URL or hash (defanged is fine)")
    choice = st.radio("Verdict", ["Confirmed malicious", "False positive (benign)"], horizontal=True)
    note = st.text_input("Note", placeholder="Ticket, sandbox result, owner confirmation…")
    if st.form_submit_button("Save verdict", type="primary", icon=":material/gavel:"):
        ioc, kind = normalize(raw)
        if not ioc:
            st.error("Enter an indicator.")
        else:
            store.set_verdict(ioc, "malicious" if choice.startswith("Confirmed") else "benign",
                              ioc_type=kind, note=note, username=username())
            st.toast(f"Verdict saved for {ioc}", icon=":material/gavel:")
            st.rerun()

with right:
    if not verdicts:
        theme.empty_state("No verdicts yet",
                          "Mark indicators as confirmed malicious or false positive from any scan result, or add one here.")
    else:
        show = st.radio("Show", ["All", "Malicious", "Benign"], horizontal=True, key="verdict_filter",
                        label_visibility="collapsed")
        rows = {"Malicious": malicious, "Benign": benign}.get(show or "All", verdicts)
        if not rows:
            st.caption(f"No {show.lower()} verdicts.")
            st.stop()
        frame = pd.DataFrame([{
            "Verdict": "Malicious" if v["verdict"] == "malicious" else "Benign",
            "Indicator": v["ioc"], "Type": v.get("type") or "", "Note": v.get("note") or "",
            "By": v.get("username") or "", "Updated": v.get("updated_at"),
        } for v in rows])
        style = frame.style
        apply = style.map if hasattr(style, "map") else style.applymap
        styled = apply(lambda x: "color:#f85149;font-weight:600" if x == "Malicious" else "color:#3fb950;font-weight:600",
                       subset=["Verdict"])
        st.dataframe(styled, hide_index=True, use_container_width=True)

        c1, c2, c3 = st.columns([1.6, 1, 1])
        target = c1.selectbox("Remove a verdict", [v["ioc"] for v in rows], key="verdict_remove",
                              label_visibility="collapsed", placeholder="Select an indicator to remove")
        if c2.button("Remove", use_container_width=True, icon=":material/delete:", disabled=not target):
            store.delete_verdict(target)
            st.toast(f"Removed verdict for {target}", icon=":material/delete:")
            st.rerun()
        lines = [f"# {('Block' if show == 'Malicious' else 'Allow' if show == 'Benign' else 'Verdict')} list "
                 f"exported {datetime.now():%Y-%m-%d %H:%M}"] + [v["ioc"] for v in rows]
        c3.download_button("Export", "\n".join(lines) + "\n", f"verdicts_{(show or 'all').lower()}.txt", "text/plain",
                           use_container_width=True, icon=":material/download:")
