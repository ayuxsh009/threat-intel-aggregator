import pandas as pd
import streamlit as st

from tia import graph
from tia.config import RISK_ORDER
from tia.ui import theme
from tia.ui.common import PAGE_SCAN, get_store, history_scope, page_link

store = get_store()
theme.page_header("Investigate", "Infrastructure graph",
                  "Indicators linked by what they share: hosting organisation, malware family, tags, hostnames "
                  "and URL hosts. Clusters reveal related infrastructure behind a single alert.")

scans = store.scans(history_scope())
if not scans:
    theme.empty_state("No data yet", "Scan some indicators and shared infrastructure will appear here.")
    st.write("")
    _, c, _ = st.columns([2, 1, 2])
    page_link(c, PAGE_SCAN, "Start scanning", ":material/radar:")
    st.stop()

f1, f2, f3 = st.columns([1.6, 2.2, 1])
present = [r for r in RISK_ORDER if any(s.get("risk") == r for s in scans)]
risks = f1.pills("Severity", present, selection_mode="multi", default=present, key="graph_risk")
links = f2.pills("Link by", list(graph.LINK_TYPES), format_func=graph.LINK_TYPES.get, selection_mode="multi",
                 default=list(graph.LINK_TYPES), key="graph_links")
min_shared = f3.number_input("Min. shared", min_value=2, max_value=10, value=2, key="graph_min",
                             help="An attribute must be shared by at least this many indicators.")

subset = [s for s in scans if s.get("risk") in (risks or [])]
g = graph.build(subset, link_types=tuple(links or ()), min_shared=int(min_shared))

theme.kpi_row([
    ("Indicators", g["total"], None, "latest result per indicator"),
    ("Linked", len(g["iocs"]), None, f"{g['total'] - len(g['iocs'])} stand alone"),
    ("Shared attributes", len(g["attrs"]), None, "clusters"),
    ("Largest cluster", max((len(a["members"]) for a in g["attrs"]), default=0), None,
     (g["clusters"][0]["label"][:30] if g["clusters"] else "—")),
])
st.write("")

if not g["edges"]:
    theme.empty_state("No shared infrastructure",
                      "None of these indicators share an organisation, malware family, tag or host yet. "
                      "Shodan and abuse.ch data make links much more likely.")
    st.stop()

with st.container(border=True):
    st.plotly_chart(graph.figure(g), use_container_width=True, config={"displayModeBar": False})
    st.caption("Circles are indicators coloured by severity; diamonds are shared attributes. Hover for details.")

st.markdown("**Clusters**")
rows = [{
    "Worst severity": c["worst"],
    "Link": graph.LINK_TYPES[c["kind"]],
    "Shared value": c["label"],
    "Indicators": len(c["members"]),
    "Members": ", ".join(c["members"][:8]) + (" …" if len(c["members"]) > 8 else ""),
} for c in g["clusters"]]
st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True,
             column_config={"Members": st.column_config.TextColumn(width="large")})
