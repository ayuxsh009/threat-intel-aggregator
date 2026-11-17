# Threat Intel Aggregator: Technical Documentation

Version 2.1.0 · last verified 2026-11-17 · 102 automated tests passing

This document explains what the application does, the technology behind it, where its data comes from, exactly how the threat score is calculated, what every chart and graph shows, and how to run, configure and test it.

---

## Contents

1. [Overview](#1-overview)
2. [Technology used](#2-technology-used)
3. [Architecture](#3-architecture)
4. [Project layout](#4-project-layout)
5. [Data sources](#5-data-sources)
6. [Indicator handling](#6-indicator-handling)
7. [How severity is decided](#7-how-severity-is-decided)
8. [The threat score formula](#8-the-threat-score-formula)
9. [Worked examples](#9-worked-examples)
10. [Workspace memory and change detection](#10-workspace-memory-and-change-detection)
11. [Analyst verdicts](#11-analyst-verdicts)
12. [Extracting indicators from text](#12-extracting-indicators-from-text)
13. [Charts and graphs explained](#13-charts-and-graphs-explained)
14. [Pages](#14-pages)
15. [Exports: PDF, CSV, STIX 2.1, block list](#15-exports-pdf-csv-stix-21-block-list)
15b. [Browser extension and API](#15b-browser-extension-and-api)
16. [Data model](#16-data-model)
17. [Accounts and security](#17-accounts-and-security)
18. [Installation, configuration and deployment](#18-installation-configuration-and-deployment)
19. [Testing](#19-testing)
20. [Limitations](#20-limitations)
21. [Changelog](#21-changelog)

---

## 1. Overview

Threat Intel Aggregator is a web application for security analysts. You give it **indicators of compromise** (IOCs): IP addresses, domains, URLs and file hashes. It then:

1. **Looks them up** in six sources at once: VirusTotal, AbuseIPDB, Shodan, abuse.ch ThreatFox, abuse.ch URLhaus and RDAP.
2. **Decides a severity**: High, Medium, Low, Legitimate, or Unknown when no source could answer.
3. **Calculates a threat score** from 0 to 100, and shows every point and the reason for it.
4. **Remembers** every indicator the workspace has scanned, and shows what changed since the last time.
5. Lets analysts **record verdicts** ("confirmed malicious", "false positive") that override the computed result from then on.
6. **Links related infrastructure** in an interactive graph.
7. **Exports** results as a PDF report, CSV, a STIX 2.1 bundle or a plain block list.
8. Shows the score and verdict **for every site you browse** through a Chrome extension backed by your own server.

The point of the app is to produce intelligence that no single source gives on its own: combined evidence, local history, analyst knowledge and relationships between indicators.

---

## 2. Technology used

| Layer | Technology | What it is used for |
|---|---|---|
| Language | **Python 3.8+** (tested on 3.8.3; Streamlit Cloud runs a newer 3.x) | All application code |
| Web framework | **Streamlit 1.40–1.45** | The whole UI: pages (`st.navigation`), forms, tabs, dialogs, interactive tables with row selection, editable tables (`st.data_editor`), pills, toasts |
| Data handling | **pandas** | Tables, filtering by date, CSV import and export, styling severity colours |
| Numerics | **NumPy** (installed with pandas) | Force-directed layout of the infrastructure graph |
| Charts | **Plotly** | Donut, stacked bars, horizontal bars, network graph |
| Chart images | **Kaleido 1.x** (uses a local Chrome/Chromium) | Turns the donut chart into a PNG for the PDF |
| PDF | **fpdf2** | Builds the report in memory |
| HTTP | **requests** | VirusTotal, AbuseIPDB, ThreatFox, URLhaus and RDAP REST APIs |
| Shodan | **shodan** (official SDK) | Host lookups |
| Database | **SQLite** (Python standard library), WAL mode | Users, settings, scan history, analyst verdicts |
| Passwords | **hashlib.pbkdf2_hmac**, **hmac.compare_digest** (standard library) | Salted hashing, constant-time comparison |
| IP validation | **ipaddress** (standard library) | Recognising IPs and filtering private or reserved ranges |
| Email | **smtplib** (standard library) | Sending PDF reports |
| STIX | Built by hand with **json** and **uuid** | No extra dependency |
| Fonts and styling | Inter and JetBrains Mono (Google Fonts), custom CSS | GitHub-style dark theme |
| Extension API | **FastAPI**, **Uvicorn** (`requirements-api.txt`) | HTTP API for the browser extension |
| Browser extension | Chrome **Manifest V3**, plain JavaScript (no build step) | Badge, corner card, warning bar, popup, settings |
| Tests | **pytest**, Streamlit **AppTest**, FastAPI **TestClient** (httpx) | Unit, API and headless UI tests |

Exact version ranges are pinned in `requirements.txt`:

```
streamlit>=1.40,<1.46
pandas>=2.0,<3
plotly>=5.24,<8
kaleido>=1.0,<2
fpdf2>=2.7,<3
requests>=2.31,<3
shodan>=1.28,<2
```

---

## 3. Architecture

```
Browser ─▶ streamlit_app.py
             ├─ not signed in ─▶ first-run setup (no users yet)  or  login form
             └─ signed in ─────▶ st.navigation ─▶ views/<page>.py
                                                    │
     views/scan.py ─▶ tia.extract (free text → IOCs, Extract tab only)
                   ─▶ tia.scanner.scan_ioc(raw, keys, store=store)
                          ├─ tia.ioc.normalize        refang, classify, canonicalise
                          ├─ tia.sources.*            VirusTotal (all types)
                          │                           AbuseIPDB + Shodan (public IPs)
                          │                           ThreatFox + URLhaus (abuse.ch key)
                          │                           RDAP (domains and URL hosts)
                          ├─ store.ioc_history ─────▶ tia.intel.sightings / tia.intel.diff
                          ├─ store.get_verdict
                          └─ tia.threatscore.assess   source verdict (tia.scoring)
                                                      + 0-100 factor score
                                                      + analyst verdict override
                                                    │
                          tia.storage.Store ─▶ data/threatintel.db (SQLite, WAL)
                                                    │
     dashboard / analytics / investigations / graph / verdicts / reports read the store
                          ├─ tia.charts   Plotly charts
                          ├─ tia.graph    infrastructure graph
                          ├─ tia.report   PDF (fpdf2) and SMTP email
                          └─ tia.export   STIX 2.1 bundle, block list
```

Design choices:

- **Logic is separate from the UI.** Everything under `tia/` except `tia/ui/` is plain Python with no Streamlit code, so it can be tested and reused from scripts.
- **Sources never raise exceptions.** Every client returns a dict with `ok: True/False`, plus `error` or `skipped: True` on failure. One failing source can't break a scan, and failures are listed on the result.
- **Results are saved as they arrive.** A batch writes each result immediately, so stopping halfway keeps the work already done.
- **Scoring is explainable by construction.** Every point of the score is a named factor object `{points, label, source}`; the UI simply lists them.

---

## 4. Project layout

```
threat-intel-aggregator/
├── streamlit_app.py           # Entry point: page config, theme, login gate, navigation
├── views/                     # One file per page
│   ├── dashboard.py
│   ├── analytics.py
│   ├── scan.py                # Single / Paste a list / Extract from text / Upload CSV
│   ├── investigations.py
│   ├── graph.py               # Infrastructure graph
│   ├── verdicts.py            # Analyst verdicts
│   ├── reports.py             # PDF, email, STIX 2.1, block list
│   └── settings.py            # API keys, users, my account, about
├── api/                       # Extension API: server.py (FastAPI), lookup.py (cache + queue), __main__.py (CLI)
├── extension/                 # Chrome extension (Manifest V3): background, content, popup, options
├── tia/                       # Application package
│   ├── config.py              # Paths, version, severity order and colours
│   ├── ioc.py                 # Refanging, type detection, list parsing
│   ├── sources.py             # API clients for all six sources
│   ├── scoring.py             # Source verdict rules
│   ├── threatscore.py         # 0-100 score, bands, escalation, verdict override
│   ├── intel.py               # Sightings and change detection
│   ├── scanner.py             # One scan end to end; flattening results into table rows
│   ├── extract.py             # IOC extraction from free text
│   ├── export.py              # STIX 2.1 bundle and block list
│   ├── graph.py               # Graph model, force layout, Plotly figure
│   ├── charts.py              # Dashboard and analytics charts
│   ├── report.py              # PDF builder and SMTP email
│   ├── storage.py             # SQLite store
│   ├── keys.py                # API key and extension token resolution without Streamlit
│   ├── auth.py                # Password hashing, validation, login, hash CLI
│   ├── legacy.py              # One-time import of version 1 JSON files
│   └── ui/
│       ├── theme.py           # CSS and small HTML components (cards, KPIs, badges)
│       ├── common.py          # Shared helpers, tables, result rendering
│       └── auth_views.py      # Login, first-run setup, sidebar user panel
├── assets/                    # logo.svg, logo_wide.svg
├── docs/screenshots/          # README images (synthetic sample data)
├── tests/                     # conftest.py, test_core.py, test_intel.py, test_ui.py
├── .streamlit/config.toml     # Dark theme
├── .streamlit/secrets.toml.example
├── requirements.txt / requirements-dev.txt
└── data/                      # Created at runtime: threatintel.db (git-ignored)
```

---

## 5. Data sources

| Source | Key needed | Queried for | What the app reads |
|---|---|---|---|
| **VirusTotal v3** (`/api/v3/search`) | Yes (free) | Every type | Malicious, suspicious, harmless and undetected engine counts; total engines; community reputation; tags; the list of engines that flagged it; a link to the VirusTotal page |
| **AbuseIPDB v2** (`/api/v2/check`, last 90 days) | Yes (free) | Public IPs | Abuse confidence score (0–100 %), report count, distinct reporters, whitelist flag, country, ISP, usage type, last report time |
| **Shodan** (host API via SDK) | Yes (free tier is limited) | Public IPs, optional in batches | Open ports, organisation, ISP, OS, country, hostnames, known CVEs, last scan date |
| **abuse.ch ThreatFox** | Yes, one free abuse.ch key | IPs, domains, URLs, hashes | Whether it is listed as malware infrastructure, malware family, threat type, confidence level, first and last seen |
| **abuse.ch URLhaus** | Same key | IPs and domains (host), URLs, MD5/SHA256 payloads | Number of malicious URLs, how many are online now, threat, tags, first seen |
| **RDAP** (`rdap.org`) | No | Domains, and the host of a URL | Registration date, age in days, registrar, expiry date |

Technical details:

- **Rate limits.** When an API answers HTTP 429, the request is retried up to 2 times, waiting for the `Retry-After` header (capped at 60 s) or 15 s × attempt. "Free-tier pacing" in batch scans waits 15.5 s between indicators to stay under VirusTotal's 4 requests per minute.
- **Errors** are classified: 401/403 means a rejected key, 429 means a rate limit, anything else shows the HTTP status and the start of the response.
- **ThreatFox matching.** ThreatFox stores IPs as `ip:port` and searches by substring, so the app keeps only true matches: for an IP, the entry must equal the IP or start with `IP:`; for a domain, it must equal the domain or be a subdomain of it.
- **RDAP domain.** The registrable domain is guessed without a suffix list: the last two labels, or the last three when the second-to-last is a common second-level label (`co`, `com`, `net`, `org`, `gov`, `ac`, `edu`, `or`, `ne`, `go`) under a two-letter country code. So `login.portal.evil.co.uk` is looked up as `evil.co.uk`.
- **Private and reserved IPs** (RFC 1918, loopback, documentation ranges and so on) are never sent to any API, because public feeds can't know about them.

---

## 6. Indicator handling

| Input | What happens |
|---|---|
| `hxxp://`, `hxxps[:]//`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`, `[/]`, `[://]` | Refanged before lookup; the original input is kept and shown |
| 32 / 40 / 64 hexadecimal characters | MD5 / SHA1 / SHA256, lower-cased |
| A valid IPv4 or IPv6 address (checked with `ipaddress`) | IP, written in canonical form |
| `scheme://...` | URL |
| A valid hostname | Domain, lower-cased, trailing dot removed |
| Anything else | Type "Unknown"; still searched on VirusTotal as free text |

Lists are split on new lines, commas, semicolons and spaces, then refanged and deduplicated in order.

---

## 7. How severity is decided

Severity is decided in three layers, applied in this order.

### Layer 1: source verdict (`tia/scoring.py`)

Each source that answered gives a level. The indicator takes **the most severe** of them.

| Source | High | Medium | Low | Legitimate |
|---|---|---|---|---|
| VirusTotal: malicious engines (all types) | ≥ 10 | 4–9 | 1–3 | 0 |
| AbuseIPDB: abuse confidence (IPs only) | ≥ 80 % | 30–79 % | 1–29 % | 0 % |
| ThreatFox: listed | confidence ≥ 50 % | confidence < 50 % | | |
| URLhaus: listed | at least one URL online now | listed, none online | | |

Rules:

- If AbuseIPDB has **whitelisted** the IP, AbuseIPDB contributes "Legitimate" instead of its level. VirusTotal detections still count.
- **Not being listed** in ThreatFox or URLhaus never sets a level. Absence from a feed is not evidence of safety.
- If **no reputation source answered** (missing keys, errors, rate limits, private IP), the result is **Unknown**. Unknown is never counted as clean.

### Layer 2: threat score escalation (`tia/threatscore.py`)

The 0–100 score (next section) is mapped to a band:

| Score | Band |
|---|---|
| 70–100 | High |
| 40–69 | Medium |
| 15–39 | Low |
| 0–14 | Legitimate |

If the band is **more severe** than the source verdict, severity is raised to the band and a reason is added, e.g. *"Combined evidence score 71/100 raised severity from Medium to High"*. If the band is less severe, nothing changes: **the score never lowers severity**. An Unknown result stays Unknown whatever the score.

### Layer 3: analyst verdict

If an analyst has saved a verdict for the indicator, it overrides both layers:

- **Confirmed malicious** → High
- **False positive (benign)** → Legitimate

The verdict is shown first among the reasons, with the analyst's name and note, and the result gets an "Analyst override" badge.

In code:

```python
rule_risk, reasons = scoring.score(kind, vt, abuse, threatfox, urlhaus)    # layer 1
factors = compute_factors(...)
score   = clamp(sum(f.points for f in factors), 0, 100)
risk    = rule_risk
if rule_risk != "Unknown" and severity(band(score)) > severity(rule_risk):
    risk = band(score)                                                      # layer 2
if verdict == "malicious": risk = "High"                                    # layer 3
if verdict == "benign":    risk = "Legitimate"
```

---

## 8. The threat score formula

The score is the **sum of the points of every factor that applies**, limited to the range 0–100:

```
threat_score = min(100, max(0, Σ factor_points))
```

Each factor's points are rounded to a whole number with Python's `round()` (exact halves round to the nearest even number, so 40.5 becomes 40). Factors worth 0 points are not shown.

### Factor table

| # | Factor | Source | Formula | Max |
|---|---|---|---|---|
| 1 | Malicious engines | VirusTotal | `4.5 × malicious` | 45 |
| 2 | Suspicious engines | VirusTotal | `2 × suspicious` | 8 |
| 3 | Negative community reputation | VirusTotal | `+5` if reputation ≤ −10 | 5 |
| 4 | Abuse confidence | AbuseIPDB (IPs, not whitelisted) | `0.35 × confidence` | 35 |
| 5 | High report volume | AbuseIPDB (IPs, not whitelisted) | `+5` if ≥ 50 reports in 90 days | 5 |
| 6 | Whitelisted | AbuseIPDB (IPs) | `−15` (replaces factors 4 and 5) | −15 |
| 7 | Risky exposed services | Shodan | `5 × number of risky ports open` | 15 |
| 8 | Known CVEs on the host | Shodan | `3 × number of CVEs` | 15 |
| 9 | Listed as malware infrastructure | ThreatFox | `+40` | 40 |
| 10 | Malware distribution | URLhaus | `+35` if a URL is online now, else `+20` | 35 |
| 11 | Young domain | RDAP | `+15` if age < 30 days, `+7` if < 180 days | 15 |
| 12 | Previously flagged here | Workspace history | `+10` if any earlier scan was High or Medium | 10 |
| 13 | Recurring indicator | Workspace history | `+3` if seen in ≥ 3 investigations | 3 |

Factors 1–3 apply only when VirusTotal found the indicator. Factors 7–8 apply only when Shodan has data for the host.

### Risky ports (factor 7)

These services should rarely face the internet and are common entry points for attackers. They are also highlighted in red on the Shodan card.

| Port | Service | Port | Service | Port | Service |
|---|---|---|---|---|---|
| 21 | FTP | 1433 | MSSQL | 5900 | VNC |
| 23 | Telnet | 2375 | Docker API | 6379 | Redis |
| 135 | MS-RPC | 3306 | MySQL | 9200 | Elasticsearch |
| 139 | NetBIOS | 3389 | RDP | 11211 | Memcached |
| 445 | SMB | 5432 | PostgreSQL | 27017 | MongoDB |

### Why these weights

- **VirusTotal is capped at 45** so that one source alone can reach the Medium band but not High. Ten engines (45 points) is already High by the layer 1 rule, so the cap never hides a real detection.
- **AbuseIPDB at 0.35 per point** means 100 % confidence gives 35. Combined with VirusTotal, two independent sources agreeing reach High.
- **Feed listings are heavy (40 and 35)** because ThreatFox and URLhaus are curated lists of confirmed malicious infrastructure.
- **Exposure, CVEs and domain age are modest (≤ 15 each)**. They are risk context, not proof of malice, so on their own they can at most reach the Low band.
- **History adds 10 at most**, so the workspace's past opinion nudges the result but can't drive it.
- **Whitelisting subtracts 15** to pull known services (public DNS resolvers, CDNs) towards zero.

---

## 9. Worked examples

These outputs come from running `tia.threatscore.assess` on the inputs shown.

**A. Two medium signals that add up (score escalates severity)**

IP with VirusTotal 9/72, AbuseIPDB 75 % from 200 reports.

| Points | Factor |
|---|---|
| +40 | 9/72 VirusTotal engines flag it as malicious (9 × 4.5 = 40.5 → 40) |
| +26 | 75 % AbuseIPDB abuse confidence (75 × 0.35 = 26.25 → 26) |
| +5 | High report volume (200 reports in 90 days) |
| **71** | **High band** |

Source verdict: Medium (VirusTotal 9 → Medium; AbuseIPDB 75 % → Medium). Final: **High**, with the reason *"Combined evidence score 71/100 raised severity from Medium to High"*.

**B. New phishing domain**

Domain with VirusTotal 3/72, registered 6 days ago, URLhaus listing with 1 URL online.

| Points | Factor |
|---|---|
| +35 | 1 malware URL online now in URLhaus |
| +15 | Domain registered 6 days ago |
| +14 | 3/72 VirusTotal engines (3 × 4.5 = 13.5 → 14) |
| **64** | Medium band |

Source verdict: High (URLhaus with a URL online). Final: **High**. The score doesn't lower it.

**C. Clean but badly exposed server**

IP with VirusTotal 0, AbuseIPDB 0 %, Shodan ports 22, 23, 445, 3389 and 3 CVEs.

| Points | Factor |
|---|---|
| +15 | Exposes Telnet (23), SMB (445), RDP (3389) (3 × 5 = 15, at the cap) |
| +9 | 3 known CVEs on this host |
| **24** | Low band |

Source verdict: Legitimate. Final: **Low**, because exposure is a real risk even with no reports.

**D. Known command-and-control server**

IP with VirusTotal 14/72 (1 suspicious, reputation −42), AbuseIPDB 100 % from 312 reports, RDP open, 1 CVE, ThreatFox "Cobalt Strike" at 90 %.

| Points | Factor |
|---|---|
| +45 | 14/72 VirusTotal engines (63 → capped at 45) |
| +40 | Listed in ThreatFox as Cobalt Strike infrastructure |
| +35 | 100 % AbuseIPDB confidence |
| +5 | Negative community reputation (−42) |
| +5 | High report volume (312 reports) |
| +5 | Exposes RDP (3389) |
| +3 | 1 known CVE |
| +2 | 1 engine marks it suspicious |
| **140 → 100** | Capped at 100 |

Final: **High**.

**E. Public DNS resolver**

IP with VirusTotal 0, AbuseIPDB whitelisted with 80 reports. Factor: −15 whitelisted. Sum −15, clamped to **0**. Final: **Legitimate**.

**F. Analyst override**

Domain with VirusTotal 12/72 (score 45, source verdict High) and a saved "false positive" verdict ("sinkhole"). Final: **Legitimate**, with the first reason *"Analyst verdict: false positive, marked benign by admin: sinkhole"*.

**G. No reputation source available**

Domain with no API keys set, registered 2 days ago. Score 15 (young domain), but no reputation source answered, so the final severity stays **Unknown**. The score is still shown for context.

---

## 10. Workspace memory and change detection

Every scan result is stored. Before scoring a new scan, the scanner loads up to 50 earlier results for the same indicator from **all users** (`Store.ioc_history`, newest first).

**Sightings** (`tia.intel.sightings`) shown on the Context card:

| Field | Meaning |
|---|---|
| Earlier scans | How many times it was scanned before |
| Investigations | In how many separate investigations it appeared |
| First seen / Last seen | Timestamps of the oldest and newest earlier scans |
| Previous severity | Severity of the most recent earlier scan |
| Worst severity | Most severe level it has ever had here (feeds score factor 12) |

**Change detection** (`tia.intel.diff`) compares the new result with the most recent earlier one and lists only what changed:

| Change reported | Condition |
|---|---|
| Severity A → B | Any change |
| Threat score A → B | Difference of 5 or more |
| VirusTotal detections A → B | Any change in malicious engines |
| AbuseIPDB confidence A% → B% | Difference of 10 points or more |
| Newly open ports / Ports closed | Shodan port set changed |
| New CVEs | CVEs not present before |
| Now listed / No longer listed in ThreatFox or URLhaus | Listing status flipped |

The changes appear in a blue "Changed since the last scan" box under the verdict card.

---

## 11. Analyst verdicts

- Saved in the `verdicts` table, one per indicator: `malicious` or `benign`, with a note, the analyst's username and the time.
- Set from the **Analyst verdict** section on any result, or on the **Verdicts** page (defanged input is accepted there).
- Applied by the scanner to **every future scan** of that indicator (layer 3 in section 7). Results already stored keep the severity they had when scanned.
- The Verdicts page can filter by verdict, remove a verdict and export the list as text (a block list or an allow list).

---

## 12. Extracting indicators from text

The **Extract from text** tab (`tia/extract.py`) takes pasted text or an uploaded `.txt`, `.log`, `.eml`, `.csv`, `.json`, `.md`, `.html` or `.xml` file.

Steps:

1. **Refang the whole text** (`hxxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`).
2. **URLs** are found first (`http`, `https`, `ftp`). Trailing punctuation and unbalanced closing brackets from surrounding prose are trimmed. URLs whose host is an XML namespace or example host are dropped.
3. URLs are blanked out so their hosts aren't reported a second time as domains.
4. **Hashes**: 64, 40 or 32 hex characters not touching other hex characters.
5. **IPv4 addresses**: dotted quads with each part 0–255. Version strings such as `1.2.3.4.5` are rejected. Private and reserved addresses are skipped unless **Include private IP addresses** is on.
6. **Domains**: hostnames with a letter TLD, ignoring:
   - file names whose "TLD" is a file extension (`invoice.pdf`, `run.ps1`, `a.exe`, `report.docx`; 71 extensions in all);
   - namespace and example hosts (`w3.org`, `schemas.microsoft.com`, `schemas.openxmlformats.org`, `purl.org`, `example.com`…).
7. Results are **deduplicated** case-insensitively and kept in the order they appear.

The extracted list is shown in an editable table with a tick box per row. Only ticked rows are scanned, and the investigation is labelled with the file name.

---

## 13. Charts and graphs explained

All charts use the same colours for severity: **High** red `#f85149`, **Medium** orange `#db6d28`, **Low** yellow `#d29922`, **Legitimate** green `#3fb950`, **Unknown** grey `#8b949e`.

### Dashboard

| Element | What it shows | How it's calculated |
|---|---|---|
| KPI: Indicators scanned | Total scan results you can see; the hint gives how many in the last 7 days | Count of results (admins see everyone's, analysts their own) |
| KPI: High / Medium / Low | How many results have each severity | Count by severity |
| KPI: No detections | Results rated Legitimate; the hint gives how many are Unknown | Count by severity |
| **Severity distribution** (donut) | Share of each severity; the centre shows the total | One slice per severity present, in fixed order High → Unknown. Hover for count and percentage |
| **Scan volume by day** (stacked bars) | How many indicators were scanned each day, split by severity | Results grouped by calendar day and severity; each bar is a day, each colour a severity. Hover shows all severities for that day |
| Recent indicators | The 8 most recent results | Newest first |

### Analytics

Pick a date range at the top (defaults to the last 30 days). Everything below uses only results in that range.

| Element | What it shows | How it's calculated |
|---|---|---|
| KPI: Indicators | Results in the period; hint: unique indicators | Count, and count of distinct values |
| KPI: Flagged | High + Medium; hint: share of all results | (High + Medium) ÷ total |
| KPI: IP addresses | Results of type IP; hint: number of domains | Count by type |
| KPI: Lookup errors | Results where at least one source failed (rate limit, bad key, network) | Results with a non-empty error list |
| **Severity distribution** (donut) | As on the dashboard, for the period | |
| **Daily volume by severity** (stacked bars) | As on the dashboard, for the period | |
| **Top detected indicators** (horizontal bars) | The 10 indicators with the most VirusTotal malicious engines | Latest result per indicator with at least 1 detection, sorted by detections; bar colour is the indicator's severity, the number at the end is the engine count |
| **Indicator types** (bars) | How many results are IP, Domain, URL, MD5, SHA1, SHA256 or Unknown | Count by type |
| High and medium severity in period | Table of every High or Medium result | Newest first |

### Infrastructure graph

This graph answers *"which of my indicators belong to the same infrastructure?"*.

**What the shapes mean:**

- **Circles** are indicators, coloured by severity. Hover shows the indicator, its type, severity and score.
- **Diamonds** are **shared attributes**: something two or more indicators have in common. Bigger diamonds are shared by more indicators. The label is the attribute's value; hover shows its link type and member count.
- **Lines** connect an indicator to an attribute it has. A line can also connect a URL directly to an IP or domain you scanned, when that is the URL's host.

**Link types** (choose any combination with the "Link by" pills):

| Link type | Where it comes from | Example |
|---|---|---|
| Hosting organisation | Shodan `org`, or AbuseIPDB `isp` if Shodan has none | Several IPs at "Bulletproof Hosting SRL" |
| Malware family | ThreatFox malware family | IPs and domains all tied to "Cobalt Strike" |
| VirusTotal tag | Up to 6 VirusTotal tags per indicator; generic tags (`malware`, `malicious`, `suspicious`, `phishing`) are ignored | Domains tagged "phishing-kit" |
| Shodan hostname | Up to 4 hostnames per host | Two IPs answering to the same hostname |
| URL host | The hostname of a URL indicator | `http://evil.example/a.exe` and `http://evil.example/b.exe` share host `evil.example` |

**How it's built** (`tia/graph.py`):

1. Take the **latest result for each indicator** (rescans don't create duplicate nodes), filtered by the chosen severities.
2. For each indicator, collect its attributes for the chosen link types.
3. Keep only attributes shared by at least **Min. shared** indicators (default 2). An attribute only one indicator has doesn't connect anything, so it's dropped.
4. Indicators with no remaining link are left out of the drawing ("stand alone" in the KPI).
5. Each cluster gets a **worst severity**: the most severe of its members.

**How it's drawn:** a Fruchterman–Reingold force-directed layout written with NumPy (no networkx):

- every pair of nodes pushes apart with force `k² / distance`;
- every line pulls its two ends together with force `distance² / k`;
- a gravity force `0.8 × |position| / k` pulls everything towards the centre, so separate clusters stay on screen;
- `k = √(4 / number of nodes)`, 250 iterations, starting step 0.2 shrinking by 1.5 % per iteration (minimum 0.005), fixed random seed 7. The same data always gives the same picture.

**Reading it:** a dense group of red circles around one diamond is a cluster of related malicious infrastructure. A grey or green indicator attached to that group deserves a closer look, because it shares infrastructure with known-bad indicators even if feeds don't flag it yet.

**KPIs above the graph:**

| KPI | Meaning |
|---|---|
| Indicators | Distinct indicators considered (after the severity filter) |
| Linked | Indicators drawn in the graph; hint: how many stand alone |
| Shared attributes | Number of diamonds (clusters) |
| Largest cluster | Members of the biggest cluster, and its value |

**Clusters table:** one row per shared attribute, sorted by worst severity then size: worst severity, link type, shared value, number of indicators, and up to 8 members.

### Charts on a result

| Element | What it shows |
|---|---|
| Threat score (top right of the verdict card) | The 0–100 score, coloured by its band |
| VirusTotal bar | Malicious engines ÷ total engines; colour by the VirusTotal level |
| AbuseIPDB bar | Abuse confidence 0–100 %; colour by the AbuseIPDB level |
| "Why this score" bar | Score ÷ 100, coloured by band, followed by every factor and its points (negative points in green) |
| Score column in tables | A small progress bar from 0 to 100 |

### PDF report chart

The PDF includes the severity donut (print colours, white background), rendered to PNG by Kaleido. If Chrome/Chromium isn't available, the report is built without it.

---

## 14. Pages

| Page | What you can do |
|---|---|
| **Dashboard** | KPIs, severity donut, daily volume, recent indicators |
| **Analytics** | Date range; KPIs; severity donut; daily volume by severity; top 10 VirusTotal detections; indicator types; table of High/Medium results |
| **Scan** | Four tabs. **Single indicator**: the full result (see below). **Paste a list**. **Extract from text**. **Upload CSV** (guesses the column named `ioc`, `indicator`, `value`, `ip`, `domain`, `url` or `hash`). Batch options: include Shodan for IPs, free-tier pacing. After a batch: severity counts, results table, CSV download, open as investigation, build report |
| **Investigations** | Pick a past scan; filter by severity pills, text and type; click a row for the full result; download CSV; build a report; delete the investigation or clear all history (with confirmation) |
| **Infrastructure graph** | See section 13 |
| **Verdicts** | KPIs (malicious, benign, contributing analysts); add or update a verdict; filter; remove; export |
| **Reports** | Pick an investigation; set a title; include the chart or not; generate and download the PDF; email it over SMTP; download a STIX 2.1 bundle or a block list for chosen severities |
| **Settings** | **API keys** (admins; shows where each key comes from; Test connections checks VirusTotal, AbuseIPDB, Shodan, ThreatFox and RDAP). **Users** (admins: add, change role, reset password, delete). **My account** (change your password). **About** |

**The full result view** contains, top to bottom:

1. **Verdict card**: severity badge (plus "Analyst override" if a verdict applies), the indicator, type, scan time, how many sources responded, VirusTotal detections, the original input if it was defanged, the threat score, and the reasons, notes and lookup errors.
2. **Changed since the last scan** box, if anything changed.
3. **VirusTotal**, **AbuseIPDB** and **Shodan** cards.
4. **Why this score**, **Threat feeds** (ThreatFox and URLhaus) and **Context** (RDAP domain registration and workspace sightings) cards.
5. **Analyst verdict** form.
6. **Vendor detections** table (engines that flagged it).
7. **Raw API responses** for all six sources.

---

## 15. Exports: PDF, CSV, STIX 2.1, block list

| Export | Where | Contents |
|---|---|---|
| **PDF** | Reports | Header, summary tiles per severity, donut chart, key findings (up to 15 High/Medium results with reasons), table of all indicators (indicator, type, risk, score, VirusTotal, abuse %, scan time), lookup problems. Built in memory with fpdf2; text is made Latin-1-safe so any language works |
| **Email** | Reports | The PDF as an attachment via SMTP. SSL on port 465 (Gmail default) or STARTTLS on other ports. Credentials are used once and never stored |
| **CSV** | Scan (batch), Investigations | One row per result: timestamp, indicator, type, severity, score, VirusTotal malicious and total, abuse confidence and reports, country, open ports, issues |
| **STIX 2.1 bundle** | Reports | An `identity` object for the author and one `indicator` per IOC. Patterns: `[ipv4-addr:value = '…']`, `[ipv6-addr:value = '…']`, `[domain-name:value = '…']`, `[url:value = '…']`, `[file:hashes.'MD5' / 'SHA-1' / 'SHA-256' = '…']` (quotes and backslashes escaped). Indicator IDs are deterministic (UUIDv5 of type and value), so re-exporting updates rather than duplicates in a TIP. `confidence` is the threat score; `labels` hold the severity and malware families; `indicator_types` is `malicious-activity` for High/Medium and `anomalous-activity` for Low; the newest result per IOC wins |
| **Block list** | Reports | Plain text with a header (title, date, severities, count), grouped by type (IP, Domain, URL, SHA256, SHA1, MD5), one indicator per line, no duplicates |
| **Verdict list** | Verdicts | Plain text list of the filtered verdicts |

---

## 15b. Browser extension and API

The Chrome extension (`extension/`) shows a score and verdict for every site you browse. It talks to a small FastAPI server (`api/`) that reuses the same scanner, scoring and database as the app.

```
page load ─▶ background.js ──GET /api/lookup?target=<host>──▶ api/server.py ─▶ api/lookup.py (LookupService)
   ▲             │ badge                                          │  cached < 24 h? ─▶ answer from the database
   │             ▼                                                │  else queue ─▶ worker thread ─▶ tia.scanner.scan_ioc
content.js ◀── result (corner card / warning bar)                 └─ saves to a daily "Browser extension" investigation
popup.js  ──POST /api/verdict──▶ store.set_verdict ─▶ applies to cached and future results
```

**API endpoints** (`python -m api`, default `http://127.0.0.1:8600`; interactive docs at `/api/docs`):

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/health` | none | Version, which sources have keys, queue length, minimum interval |
| `GET /api/lookup?target=<url or host>&force=false` | token | Returns `ready` (with the result), `pending` (queue position, ETA, and the previous result if any), `skipped` (with a reason) or `error` |
| `POST /api/verdict` `{target, verdict: "malicious" \| "benign" \| null, note}` | token | Sets or clears the analyst verdict and returns the updated lookup |
| `GET /api/auth-check` | token | Lets the extension verify its token |

**Authentication.** Requests carry `X-TI-Token: <token>` (or `Authorization: Bearer <token>`), compared in constant time. The token comes from `TI_API_TOKEN`, then `[api] token` in secrets, then the `api.token` app setting, which is generated (24 random bytes, URL-safe) on first use. `python -m api token` prints it; `python -m api token --new` replaces it; admins can view or regenerate it in **Settings → Browser extension**. CORS only allows `chrome-extension://`, `moz-extension://` and `safari-web-extension://` origins, and the server binds to `127.0.0.1` unless `--host` is given.

**Host normalisation** (`api/lookup.normalize_target`): the URL is reduced to its host name; `www.` is dropped; non-HTTP schemes, private or reserved IPs, `localhost`, single-label names and internal suffixes (`.local`, `.localhost`, `.internal`, `.lan`, `.home`, `.home.arpa`, `.corp`, `.test`, `.invalid`, `.example`) are skipped. The extension applies the same filter before sending anything, plus the user's skip list.

**Caching and rate limiting.** A result younger than 24 hours is returned straight from the database. Otherwise the host joins a queue processed by one background thread. When a VirusTotal key is set, lookups are spaced **15.5 seconds** apart (the free tier allows 4 per minute); without one there is no wait. Shodan is not queried for extension lookups to save quota. The extension's service worker also keeps ready answers for 10 minutes and de-duplicates simultaneous requests. While a host is pending, the card shows "Checking…" (or the previous result marked "refreshing") and re-asks every few seconds.

**Verdicts in the extension.** Every answer is re-scored with the *current* verdict, so marking a site as a false positive turns its cached result green immediately (the badge shows `OK`), and clearing the verdict restores the computed severity.

**What the user sees:**

| Element | Behaviour |
|---|---|
| Badge | Score 0–100 coloured by severity; `OK` (analyst marked safe), `?` (unknown), `…` (checking), `!` (setup needed), `×` (server unreachable), blank (not checked) |
| Corner card | Severity label, score, up to 3 reasons and the domain age if under 180 days. Hides after 6 s (Legitimate/Unknown), 9 s (Low) or 15 s (Medium); hovering keeps it open. Modes: every site, risky sites only (Medium), badge only |
| Warning bar | For High severity in every mode, even on sites where the card is hidden: score, first reason, **Leave site**, **I understand, continue** |
| Popup | Severity, score bar, analyst verdict, changes since the last check, reasons, score breakdown, VirusTotal/AbuseIPDB/domain age/registrar/ThreatFox/URLhaus/workspace sightings, verdict buttons with a note, **Re-check now**, link to VirusTotal, **Open app** |
| Settings | API address (other hosts need an optional permission), token, app address, card mode, skip list, hidden-card list, **Save and test** |

The card and bar are drawn inside a closed shadow DOM, so page styles can't change them and page scripts can't read them. They are built with DOM methods, never `innerHTML`, so result text can't inject markup.

---

## 16. Data model

SQLite file `data/threatintel.db` (change the folder with `TI_DATA_DIR`), WAL journaling, foreign keys on.

| Table | Columns | Notes |
|---|---|---|
| `users` | `username` (primary key, case-insensitive), `password_hash`, `role`, `created_at` | Roles: `admin`, `analyst` |
| `settings` | `key` (primary key), `value` | API keys saved in the UI (`apikey.vt`, `apikey.abuseipdb`, `apikey.shodan`, `apikey.abusech`), the extension token (`api.token`) and internal flags |
| `sessions` | `id`, `username`, `kind`, `label`, `created_at` | One per investigation; `kind` is `single`, `list`, `csv`, `extract` or `extension` (one per day, user `browser`) |
| `scans` | `id`, `session_id` (cascade delete), `username`, `ioc`, `type`, `risk`, `timestamp`, `data` | `data` holds the full result as JSON. Indexed on session, user and IOC |
| `verdicts` | `ioc` (primary key), `type`, `verdict` (`malicious` or `benign`), `note`, `username`, `updated_at` | One verdict per indicator; saving again replaces it |

A stored result (`data`) contains: `timestamp`, `input`, `ioc`, `type`, `risk`, `rule_risk`, `score`, `factors`, `reasons`, `notes`, `errors`, `skipped`, `verdict`, `sightings`, `changes`, and the raw responses `vt`, `abuse`, `shodan`, `threatfox`, `urlhaus`, `rdap`.

---

## 17. Accounts and security

- **No default password.** On first launch you create the administrator.
- **Password hashing:** PBKDF2-SHA256, 260,000 iterations, 16-byte random salt, stored as `pbkdf2_sha256$260000$<salt>$<hex digest>`. Checked with a constant-time comparison. Unknown usernames are checked against a dummy hash, so response time doesn't reveal which usernames exist.
- **Password rules:** at least 8 characters, not all digits or all letters. Usernames: 3–32 characters from letters, digits, `.`, `_`, `-`.
- **Login lockout:** after 5 failed attempts, sign-in is paused for 30 seconds in that browser session.
- **Roles:**

| Capability | Admin | Analyst |
|---|:---:|:---:|
| Scan, investigate, analytics, graph, reports, verdicts | ✔ | ✔ |
| Scan history visible | Everyone's | Own only |
| Change API keys | ✔ | — |
| Manage users | ✔ | — |
| Change own password | ✔ | ✔ |

- **Users in secrets:** `[credentials] users = [{ username, role, password_hash }]`. Generate a hash with `python -m tia.auth`. Plain-text `password` still works, but the sidebar warns.
- **API keys** saved on the Settings page are stored unencrypted in the database. Prefer secrets or environment variables on shared machines. `data/` and `.streamlit/secrets.toml` are git-ignored.
- **Workspace memory is shared:** sightings and verdicts come from all users, so analysts benefit from each other's work (an analyst still sees only their own investigations).

---

## 18. Installation, configuration and deployment

### Install and run

```bash
git clone https://github.com/ayuxsh009/threat-intel-aggregator.git
cd threat-intel-aggregator
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run streamlit_app.py           # http://localhost:8501
```

1. Create the admin account on first launch.
2. Add API keys in **Settings → API keys**, then click **Test connections**.
3. Optional: install Chrome or Chromium for the chart in PDFs.

### Configuration

| Setting | How |
|---|---|
| API keys | `[apikeys]` with `VT`, `AbuseIPDB`, `Shodan`, `AbuseCH` in `.streamlit/secrets.toml` → environment variables `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `ABUSECH_API_KEY` → Settings page. The first one found wins. RDAP needs no key |
| Users outside the database | `[credentials] users = [...]` in secrets |
| Data folder | `TI_DATA_DIR` (default `./data`) |
| Theme | `.streamlit/config.toml` |

Example secrets file:

```toml
[apikeys]
VT = "your_virustotal_api_key"
AbuseIPDB = "your_abuseipdb_api_key"
Shodan = "your_shodan_api_key"
AbuseCH = "your_abuse_ch_auth_key"

[credentials]
users = [
  { username = "admin", role = "admin", password_hash = "pbkdf2_sha256$260000$..." },
]
```

### Where to get keys

| Service | Sign up | Key location |
|---|---|---|
| VirusTotal | virustotal.com/gui/join-us | Profile menu → API key |
| AbuseIPDB | abuseipdb.com/register | Account → API → Create Key |
| Shodan | account.shodan.io/register | Account page |
| abuse.ch | auth.abuse.ch | Optional → Auth-Key (one key for ThreatFox and URLhaus) |

### Deployment

- **Local or internal server:** `streamlit run streamlit_app.py --server.headless true`. Keep `data/` on persistent storage and back it up.
- **Streamlit Community Cloud:** point it at `streamlit_app.py` and paste the secrets file into **Advanced settings → Secrets**. Always define a `[credentials]` user, otherwise the first visitor can create the admin account. Storage is temporary: history, sightings and verdicts reset when the app restarts or sleeps, and the PDF chart is skipped (no Chrome). After a code update, use **Manage app → Reboot app** so all modules reload.
- **Vercel** can't host Streamlit (it needs a long-running server with WebSockets).
- **Upgrading from version 1:** `configure.json`, `apikeys.json` and `scan_log.json` in the project folder are imported once when the database is created.

---

## 19. Testing

```bash
pip install -r requirements-dev.txt
pytest
```

Result on 2026-11-18 (Windows 11, Python 3.8.3, Streamlit 1.40.1, FastAPI 0.124): **126 passed**.

| Suite | Tests | Covers |
|---|---|---|
| `tests/test_core.py` | 57 | Type detection and refanging; every source rule; VirusTotal, AbuseIPDB and Shodan parsing with mocked HTTP (success, not found, 401, 429 retry and give-up, network error); scanner; hashing, validation and login; sessions and per-user scope; legacy import; PDF with Unicode and many rows; charts; SMTP |
| `tests/test_intel.py` | 23 | ThreatFox (including `ip:port` matching), URLhaus and RDAP parsing; every score factor and cap; escalation without downgrade; whitelist; feed rules; analyst overrides; sightings and diff; history and verdict storage; scanner with a store; extraction from noisy text; STIX patterns, escaping and labels; block lists; graph clusters, URL-host links and deterministic layout |
| `tests/test_api.py` | 23 | Host normalisation and skipping; queue then cache; stale result shown while refreshing; forced re-checks and queue positions; current verdict applied to cached results; worker errors; free-tier interval; health, token check (header and bearer), skip and verdict over HTTP; CORS allowed for extensions only; token generation and precedence |
| `tests/test_ui.py` | 23 | First-run setup; login and lockout; every page with and without data; single scan; pasted batch; extract-from-text flow; saving a verdict and seeing it override the next scan; verdicts page; graph page; investigation table; PDF and export downloads; API keys and users; password change; browser-extension token tab; analyst restrictions |

Notes:

- No test calls a real API; all sources are mocked. RDAP is stubbed by a fixture because it needs no key.
- A fixture ignores any real `.streamlit/secrets.toml`, so a developer's own keys and users can't affect results.
- Streamlit 1.40's AppTest doesn't run pages registered with `st.navigation`, so UI tests run each `views/*.py` file directly with a signed-in session. Navigation was checked separately in headless Chrome with a seeded database: every page loaded with no errors and no failed requests.

The extension itself was tested end to end in Chromium (Playwright with the unpacked extension loaded) against the real API server with faked threat data: settings save and connection test, badges for clean / low / high sites, the corner card, the high-risk warning bar, the popup, and marking a false positive (badge changes to `OK`), with no page errors.

Not covered automatically: live calls with real keys and sending a real email.

---

## 20. Limitations

- **Free API limits:** VirusTotal allows about 4 lookups per minute and 500 per day on a free key; large batches need pacing. Free Shodan accounts have limited host access.
- **RDAP domain guessing** doesn't use the full public suffix list, so unusual suffixes may be looked up at the wrong level.
- **The score's weights are fixed** in `tia/threatscore.py`. They are a reasoned default, not a trained model.
- **Stored results don't change** when a verdict is added later; the verdict applies to new scans.
- **No background rescans:** change detection happens when an indicator is scanned again.
- **Streamlit Cloud** storage is temporary (see section 18), and it can't run the extension API.
- **Extension lookups are rate limited** by your VirusTotal plan: on a free key, a burst of new sites queues 15.5 s apart.
- **The extension is loaded unpacked** (developer mode); it is not on the Chrome Web Store.

---

## 21. Changelog

### 2.1: browser extension

| Area | Change |
|---|---|
| Extension | Chrome Manifest V3 extension: score badge, corner card, high-risk warning bar, popup with verdict buttons, settings with skip list |
| API | `python -m api`: FastAPI server with token auth, extension-only CORS, 24-hour cache, rate-limited queue, verdict endpoint |
| App | **Settings → Browser extension** tab to view or regenerate the token; `tia/keys.py` shares key and token resolution between app and API |
| Tests | 102 → 126, plus an end-to-end browser run |

### 2.0 → 2.1: intelligence features

| Area | Change |
|---|---|
| Sources | abuse.ch ThreatFox and URLhaus with one optional key; RDAP with no key |
| Scoring | Explainable 0–100 score, severity bands, escalation without downgrade |
| Memory | Sightings across the workspace; diff against the previous scan |
| Verdicts | Verdicts table, form on every result, Verdicts page, override in later scans |
| Extraction | Defang-aware IOC extraction from text with noise filtering |
| Graph | Infrastructure graph page with clusters |
| Exports | STIX 2.1 bundle and block list |
| UI | Score column, score in PDF, risky ports highlighted, override badge, abuse.ch and RDAP in source status and connection test |
| Tests | 73 → 102 |

### 1 → 2.0: rewrite

| # | Version 1 problem | Fix in 2.0 |
|---|---|---|
| 1 | AbuseIPDB thresholds were applied to the report count | Thresholds use the abuse confidence score |
| 2 | AbuseIPDB 0 % (or no key) made any IP "Legitimate", even with 40 VirusTotal hits | Most severe source wins; whitelisting only cancels AbuseIPDB |
| 3 | Errors and rate limits scored as clean | Unknown verdict, per-result errors, retry on 429, free-tier pacing |
| 4 | Plain-text passwords, default `admin/admin` | PBKDF2 hashing, first-run setup, roles, lockout |
| 5 | Files with keys not git-ignored | Git-ignored `data/` SQLite database |
| 6 | Non-Latin characters crashed the PDF | Latin-1-safe text; fpdf2 |
| 7 | PDF and PNG files written on every Reports visit | PDF built in memory on request |
| 8 | Defanged IOCs not cleaned | Full refanging |
| 9 | Loose IP regex | `ipaddress` validation; private ranges skipped |
| 10 | No Shodan in batch scans | Optional Shodan toggle |
| 11 | Unpinned requirements, unused package | Version ranges; unused package removed |
| 12 | One shared JSON file for all users | SQLite with WAL and per-user history |
| — | URL special characters broke VirusTotal queries | Query parameters encoded |
| — | 880-line single file | `tia/` package, one file per page, tests |
