import time
from datetime import datetime

import pandas as pd
import streamlit as st

from tia.extract import extract
from tia.ioc import parse_list
from tia.scanner import scan_ioc
from tia.ui import theme
from tia.ui.common import (PAGE_INVESTIGATIONS, PAGE_REPORTS, api_keys, csv_bytes, display_frame,
                           get_store, render_result, show_table, source_status, summary_pills, username)

VT_FREE_DELAY = 15.5  # VirusTotal public API: 4 requests per minute
BIG_BATCH = 100

store = get_store()
keys = api_keys(store)

theme.page_header(
    "Investigate", "Scan",
    "Look up IPs, domains, URLs and file hashes, or paste a whole email or report to extract them. "
    "Defanged input (hxxp://, [.]) is accepted.",
)
source_status(store)
if not any(keys.values()):
    st.warning("No API keys are configured, so every result will be **Unknown**. Add keys in Settings.", icon=":material/key:")


def run_batch(iocs: list, kind: str, label: str, use_shodan: bool, pace: bool) -> None:
    sid = store.create_session(username(), kind, label)
    results = []
    with st.status(f"Scanning {len(iocs)} indicators…", expanded=True) as status:
        progress = st.progress(0.0)
        line = st.empty()
        for i, ioc in enumerate(iocs):
            line.markdown(f"`{ioc}` · {i + 1} of {len(iocs)}")
            result = scan_ioc(ioc, keys, use_shodan=use_shodan, store=store)
            store.add_scan(sid, username(), result)  # saved as we go, so a crash keeps partial results
            results.append(result)
            progress.progress((i + 1) / len(iocs))
            if pace and keys.get("vt") and i < len(iocs) - 1:
                time.sleep(VT_FREE_DELAY)
        line.empty()
        status.update(label=f"Scanned {len(iocs)} indicators", state="complete", expanded=False)
    st.session_state["batch_result"] = {"session": sid, "results": results}
    st.session_state["selected_session"] = sid


def batch_options(prefix: str) -> tuple:
    c1, c2 = st.columns(2)
    shodan = c1.toggle("Include Shodan for IPs", value=bool(keys.get("shodan")), key=f"{prefix}_shodan",
                       help="Adds open ports and host details. Slower, and uses Shodan quota.")
    pace = c2.toggle("Free-tier pacing", value=False, key=f"{prefix}_pace",
                     help="Waits 15 s between lookups to stay under VirusTotal's free limit (4 per minute).")
    return shodan, pace


def show_batch_result() -> None:
    batch = st.session_state.get("batch_result")
    if not batch:
        return
    results = batch["results"]
    st.write("")
    st.markdown("**Batch results**")
    summary_pills(results)
    show_table(display_frame(results))
    failed = sum(1 for r in results if r.get("errors"))
    if failed:
        st.warning(f"{failed} lookups hit errors (often rate limits). They are marked **Unknown**, not clean.", icon=":material/warning:")
    c1, c2, c3, _ = st.columns([1, 1, 1, 2])
    c1.download_button("Download CSV", csv_bytes(results), f"scan_{datetime.now():%Y%m%d_%H%M%S}.csv",
                       "text/csv", use_container_width=True, icon=":material/download:")
    if c2.button("Open investigation", use_container_width=True, icon=":material/manage_search:"):
        st.switch_page(PAGE_INVESTIGATIONS)
    if c3.button("Build report", use_container_width=True, icon=":material/picture_as_pdf:"):
        st.switch_page(PAGE_REPORTS)


single, paste, extract_tab, upload = st.tabs(["Single indicator", "Paste a list", "Extract from text", "Upload CSV"])

with single:
    with st.form("single_scan", border=False):
        c1, c2 = st.columns([5, 1])
        raw = c1.text_input("Indicator", label_visibility="collapsed",
                            placeholder="IP, domain, URL or hash, e.g. 198.51.100.23 or evil[.]com")
        go = c2.form_submit_button("Scan", type="primary", use_container_width=True, icon=":material/search:")
    if go:
        if not raw.strip():
            st.warning("Enter an indicator to scan.")
        else:
            with st.spinner("Querying threat-intel sources…"):
                result = scan_ioc(raw, keys, store=store)
                sid = store.create_session(username(), "single", result["ioc"])
                store.add_scan(sid, username(), result)
                st.session_state["single_result"] = result
                st.session_state["selected_session"] = sid
    if st.session_state.get("single_result"):
        st.write("")
        render_result(st.session_state["single_result"])

with paste:
    text = st.text_area("Indicators", height=180, label_visibility="collapsed",
                        placeholder="One per line, or separated by commas or spaces.\n8.8.8.8\nexample[.]com\n44d88612fea8a8f36de82e1278abb02f")
    iocs = parse_list(text)
    shodan_p, pace_p = batch_options("paste")
    st.caption(f"{len(iocs)} unique indicators detected" if iocs else "Duplicates are removed automatically.")
    if len(iocs) > BIG_BATCH and not pace_p:
        st.info("Large batch: free API keys will hit rate limits. Consider free-tier pacing.", icon=":material/info:")
    if st.button("Scan list", type="primary", disabled=not iocs, key="scan_paste", icon=":material/play_arrow:"):
        run_batch(iocs, "list", f"Pasted list ({len(iocs)})", shodan_p, pace_p)

with extract_tab:
    st.caption("Paste an email, alert, log excerpt or threat report, or drop a text file. "
               "Indicators are pulled out automatically; file names and private or reserved IPs are ignored.")
    doc = st.file_uploader("Text file", type=["txt", "log", "eml", "csv", "json", "md", "html", "xml"],
                           key="extract_file", label_visibility="collapsed")
    body = st.text_area("Text", height=200, key="extract_text", label_visibility="collapsed",
                        placeholder="Paste any text, e.g.\nThe payload was fetched from hxxp://cdn-update[.]top/a.exe "
                                    "and beaconed to 203.0.113[.]77:443 (SHA256 9f86d0...)")
    source_text = body
    if doc is not None:
        source_text = doc.getvalue().decode("utf-8", errors="ignore") + "\n" + body
    keep_private = st.toggle("Include private IP addresses", value=False, key="extract_private")
    found = extract(source_text, include_private=keep_private) if source_text.strip() else []
    if found:
        by_type = pd.Series([f["type"] for f in found]).value_counts()
        st.caption(f"Found {len(found)} indicators · " + " · ".join(f"{n} {t}" for t, n in by_type.items()))
        picked = st.data_editor(
            pd.DataFrame({"Scan": True, "Indicator": [f["ioc"] for f in found], "Type": [f["type"] for f in found]}),
            hide_index=True, use_container_width=True, key="extract_editor",
            column_config={"Scan": st.column_config.CheckboxColumn(width="small")},
            disabled=["Indicator", "Type"],
        )
        chosen = picked.loc[picked["Scan"], "Indicator"].tolist()
        shodan_x, pace_x = batch_options("extract")
        if st.button(f"Scan {len(chosen)} selected", type="primary", disabled=not chosen, key="scan_extract",
                     icon=":material/play_arrow:"):
            label = f"Extracted from {doc.name}" if doc is not None else f"Extracted from text ({len(chosen)})"
            run_batch(chosen, "extract", label, shodan_x, pace_x)
    elif source_text.strip():
        st.info("No indicators found in this text.", icon=":material/info:")

with upload:
    file = st.file_uploader("CSV file", type=["csv"], label_visibility="collapsed")
    if file is not None:
        try:
            frame = pd.read_csv(file)
        except Exception as exc:
            st.error(f"Could not read the CSV: {exc}")
            frame = None
        if frame is not None and not frame.empty:
            text_cols = frame.select_dtypes(include="object").columns.tolist() or frame.columns.tolist()
            guess = next((c for c in text_cols if str(c).lower() in ("ioc", "indicator", "value", "ip", "domain", "url", "hash")), text_cols[0])
            column = st.selectbox("Column with indicators", text_cols, index=text_cols.index(guess))
            csv_iocs = parse_list("\n".join(frame[column].dropna().astype(str)))
            st.caption(f"{len(csv_iocs)} unique indicators in “{column}” · {file.name}")
            shodan_u, pace_u = batch_options("csv")
            if st.button("Start batch scan", type="primary", disabled=not csv_iocs, key="scan_csv", icon=":material/play_arrow:"):
                run_batch(csv_iocs, "csv", file.name, shodan_u, pace_u)
        elif frame is not None:
            st.warning("The CSV file is empty.")

show_batch_result()
