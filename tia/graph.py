"""Infrastructure pivot graph.

Indicators are linked through what they share: hosting organisation, malware
family, VirusTotal tags, Shodan hostnames and URL hosts. Shared attributes are
how one bad IP leads to a whole cluster of related infrastructure.
"""

from __future__ import annotations

import math
from urllib.parse import urlsplit

import numpy as np
import plotly.graph_objects as go

from .config import RISK_COLORS
from .scoring import _SEVERITY

LINK_TYPES = {
    "org": "Hosting organisation",
    "family": "Malware family",  # from ThreatFox; URLhaus only says "malware_download"
    "tag": "VirusTotal tag",
    "hostname": "Shodan hostname",
    "host": "URL host",
}
_GENERIC_TAGS = {"malware", "malicious", "suspicious", "phishing"}  # too broad to cluster on


def latest_per_ioc(results: list[dict]) -> list[dict]:
    latest: dict[str, dict] = {}
    for r in results:
        if r.get("ioc"):
            latest[r["ioc"]] = r  # results are oldest first, so the last one wins
    return list(latest.values())


def attributes(r: dict) -> set[tuple[str, str]]:
    """(link type, value) pairs describing an indicator's infrastructure."""
    out: set[tuple[str, str]] = set()
    shodan, abuse = r.get("shodan") or {}, r.get("abuse") or {}
    org = (shodan.get("org") if shodan.get("ok") else None) or (abuse.get("isp") if abuse.get("ok") else None)
    if org:
        out.add(("org", str(org)))
    for fam in (r.get("threatfox") or {}).get("families", []) or []:
        out.add(("family", str(fam)))
    vt = r.get("vt") or {}
    for tag in (vt.get("tags") or [])[:6]:
        if str(tag).lower() not in _GENERIC_TAGS:
            out.add(("tag", str(tag)))
    if shodan.get("ok"):
        for h in (shodan.get("hostnames") or [])[:4]:
            out.add(("hostname", str(h).lower()))
    if r.get("type") == "URL":
        host = (urlsplit(r["ioc"]).hostname or "").lower()
        if host:
            out.add(("host", host))
    return out


def build(results: list[dict], *, link_types=tuple(LINK_TYPES), min_shared: int = 2) -> dict:
    """Nodes, edges and clusters. Attributes shared by fewer than ``min_shared``
    indicators are dropped, since they don't connect anything."""
    iocs = latest_per_ioc(results)
    ioc_names = {r["ioc"].lower() for r in iocs}
    members: dict[tuple[str, str], list[dict]] = {}
    for r in iocs:
        for kind, value in attributes(r):
            if kind in link_types:
                members.setdefault((kind, value), []).append(r)

    edges, attr_nodes, direct = [], [], []
    for (kind, value), rs in members.items():
        # A URL host that is itself a scanned indicator links directly.
        if kind == "host" and value in ioc_names:
            for r in rs:
                direct.append((r["ioc"], value))
            continue
        if len(rs) < min_shared:
            continue
        node_id = f"{kind}:{value}"
        worst = max((x.get("risk", "Unknown") for x in rs), key=lambda k: _SEVERITY.get(k, -1))
        attr_nodes.append({"id": node_id, "kind": kind, "label": value, "members": [x["ioc"] for x in rs],
                           "worst": worst})
        edges += [(x["ioc"], node_id) for x in rs]

    by_lower = {r["ioc"].lower(): r["ioc"] for r in iocs}
    edges += [(a, by_lower[b]) for a, b in direct if by_lower[b] != a]
    linked = {x for edge in edges for x in edge}
    ioc_nodes = [r for r in iocs if r["ioc"] in linked]
    clusters = sorted(attr_nodes, key=lambda n: (-_SEVERITY.get(n["worst"], -1), -len(n["members"])))
    return {"iocs": ioc_nodes, "attrs": attr_nodes, "edges": edges, "clusters": clusters,
            "total": len(iocs)}


def layout(node_ids: list[str], edges: list[tuple[str, str]], *, iterations: int = 250, seed: int = 7) -> dict:
    """Small Fruchterman-Reingold force layout (no networkx dependency)."""
    n = len(node_ids)
    if n == 0:
        return {}
    if n == 1:
        return {node_ids[0]: (0.0, 0.0)}
    index = {k: i for i, k in enumerate(node_ids)}
    rng = np.random.default_rng(seed)
    pos = rng.uniform(-1, 1, (n, 2))
    pairs = np.array([(index[a], index[b]) for a, b in edges if a in index and b in index], dtype=int).reshape(-1, 2)
    k = math.sqrt(4.0 / n)
    temp = 0.2
    for _ in range(iterations):
        delta = pos[:, None, :] - pos[None, :, :]
        dist = np.linalg.norm(delta, axis=-1) + 1e-6
        disp = ((k * k / dist ** 2)[:, :, None] * delta).sum(axis=1)
        if len(pairs):
            d = pos[pairs[:, 0]] - pos[pairs[:, 1]]
            ln = np.linalg.norm(d, axis=1)[:, None] + 1e-6
            pull = d * ln / k
            np.add.at(disp, pairs[:, 0], -pull)
            np.add.at(disp, pairs[:, 1], pull)
        disp -= pos * np.linalg.norm(pos, axis=1)[:, None] * 0.8 / k  # gravity keeps components together
        length = np.linalg.norm(disp, axis=1)[:, None] + 1e-6
        pos += disp / length * np.minimum(length, temp)
        pos -= pos.mean(axis=0)
        temp = max(temp * 0.985, 0.005)
    return {node_ids[i]: (float(pos[i, 0]), float(pos[i, 1])) for i in range(n)}


def figure(graph: dict) -> go.Figure:
    ioc_ids = [r["ioc"] for r in graph["iocs"]]
    attr_ids = [a["id"] for a in graph["attrs"]]
    pos = layout(ioc_ids + attr_ids, graph["edges"])

    ex, ey = [], []
    for a, b in graph["edges"]:
        if a in pos and b in pos:
            ex += [pos[a][0], pos[b][0], None]
            ey += [pos[a][1], pos[b][1], None]
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=ex, y=ey, mode="lines", hoverinfo="skip", showlegend=False,
                             line=dict(color="rgba(139,148,158,.35)", width=1)))

    if graph["attrs"]:
        fig.add_trace(go.Scatter(
            x=[pos[a][0] for a in attr_ids], y=[pos[a][1] for a in attr_ids], mode="markers+text",
            name="Shared attribute", text=[a["label"][:28] for a in graph["attrs"]], textposition="top center",
            textfont=dict(size=10, color="#8b949e"),
            marker=dict(symbol="diamond", size=[10 + 2 * min(len(a["members"]), 10) for a in graph["attrs"]],
                        color="#30363d", line=dict(color="#8b949e", width=1)),
            hovertext=[f"<b>{LINK_TYPES[a['kind']]}</b><br>{a['label']}<br>{len(a['members'])} indicators"
                       for a in graph["attrs"]],
            hoverinfo="text",
        ))

    for risk, color in RISK_COLORS.items():
        rs = [r for r in graph["iocs"] if r.get("risk", "Unknown") == risk]
        if not rs:
            continue
        fig.add_trace(go.Scatter(
            x=[pos[r["ioc"]][0] for r in rs], y=[pos[r["ioc"]][1] for r in rs], mode="markers", name=risk,
            marker=dict(size=13, color=color, line=dict(color="#0d1117", width=1.5)),
            hovertext=[f"<b>{r['ioc']}</b><br>{r.get('type')} · {risk}"
                       + (f" · score {r['score']}" if isinstance(r.get("score"), int) else "") for r in rs],
            hoverinfo="text",
        ))

    fig.update_layout(
        height=560, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#8b949e", size=12),
        xaxis=dict(visible=False), yaxis=dict(visible=False, scaleanchor="x"),
        legend=dict(orientation="h", y=1.02, x=0, bgcolor="rgba(0,0,0,0)"), hoverlabel=dict(bgcolor="#161b22"),
    )
    return fig

