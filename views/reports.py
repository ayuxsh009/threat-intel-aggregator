import re
from datetime import datetime

import streamlit as st

from tia import charts
from tia.report import build_pdf, send_email
from tia.ui import theme
from tia.ui.common import (page_link, COLUMN_CONFIG, PAGE_SCAN, display_frame, get_store, risk_counts, session_picker,
                           summary_pills, username)

EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

store = get_store()
theme.page_header("Output", "Reports", "Turn an investigation into a PDF you can download or email.")

sid, _ = session_picker(store, key="report_session")
if not sid:
    theme.empty_state("📄", "Nothing to report yet", "Run a scan first; every scan can become a report.")
    st.write("")
    _, c, _ = st.columns([2, 1, 2])
    page_link(c, PAGE_SCAN, "Start scanning", ":material/radar:")
    st.stop()

results = store.session_results(sid)
session = store.get_session(sid) or {}
summary_pills(results)

left, right = st.columns([1.15, 1])
with left, st.container(border=True):
    st.markdown("**Report options**")
    title = st.text_input("Title", value=f"Threat report: {session.get('label') or 'scan'}"[:80], key=f"title_{sid}")
    include_chart = st.toggle("Include risk chart", value=True, key=f"chart_{sid}",
                              help="Needs Kaleido and a local Chrome/Chromium install; skipped automatically if unavailable.")
    if st.button("Generate PDF", type="primary", icon=":material/picture_as_pdf:", key=f"gen_{sid}"):
        with st.spinner("Building report…"):
            png = charts.chart_png(charts.risk_donut(risk_counts(results), print_mode=True), width=700, height=380) if include_chart else None
            pdf = build_pdf(results, title=title, author=username(), chart_png=png)
        st.session_state[f"pdf_{sid}"] = {"bytes": pdf, "name": f"TI_Report_{datetime.now():%Y%m%d_%H%M%S}.pdf"}
        if include_chart and png is None:
            st.info("Chart skipped: Kaleido could not find Chrome/Chromium.", icon="ℹ️")
    ready = st.session_state.get(f"pdf_{sid}")
    if ready:
        st.download_button("Download PDF", ready["bytes"], ready["name"], "application/pdf",
                           use_container_width=True, icon=":material/download:", key=f"dl_{sid}")
        st.caption(f"{ready['name']} · {len(ready['bytes']) / 1024:.0f} KB")

with right, st.container(border=True):
    st.markdown("**Email the report**")
    if not ready:
        st.caption("Generate the PDF first.")
    with st.form(f"email_{sid}", border=False):
        recipient = st.text_input("Recipient", placeholder="soc-team@company.com")
        sender = st.text_input("Sender address", placeholder="you@gmail.com")
        password = st.text_input("App password", type="password",
                                 help="For Gmail, create an App Password under Google Account > Security.")
        with st.expander("SMTP server"):
            host = st.text_input("Host", value="smtp.gmail.com")
            port = st.number_input("Port", value=465, step=1, help="465 = SSL, 587 = STARTTLS")
        send = st.form_submit_button("Send", disabled=not ready, use_container_width=True, icon=":material/send:")
    if send and ready:
        if not (EMAIL.match(recipient or "") and EMAIL.match(sender or "") and password):
            st.error("Enter a valid recipient, sender address and app password.")
        else:
            try:
                with st.spinner("Sending…"):
                    send_email(ready["bytes"], ready["name"], recipient=recipient, sender=sender,
                               password=password, host=host, port=int(port), subject=title)
                st.success(f"Report sent to {recipient}.")
            except Exception as exc:
                st.error(f"Could not send the email: {exc}")

st.markdown("#### Contents")
st.dataframe(display_frame(results), hide_index=True, use_container_width=True, column_config=COLUMN_CONFIG)
