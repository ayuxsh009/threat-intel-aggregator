# Threat Intel Aggregator — Technical Documentation

Version 2.1.0 · last verified 2026-11-17

Threat Intel Aggregator is a Streamlit web app for security analysts. It takes indicators of compromise (IOCs), looks them up in **VirusTotal**, **AbuseIPDB**, **Shodan**, **abuse.ch ThreatFox and URLhaus** and **RDAP**, and gives each a severity (High, Medium, Low, Legitimate, or Unknown when no source could answer) plus an explainable **0–100 threat score**. It remembers every indicator the workspace has seen, highlights what changed since the last scan, lets analysts record verdicts that override computed results, extracts indicators from free text, links related infrastructure in a graph, and exports to PDF, CSV, STIX 2.1 or a block list.

---

## 1. Tech stack

| Layer | Technology | Used for |
|---|---|---|
| Language | Python 3.8+ (tested on 3.8.3) | Everything |
| UI | Streamlit 1.40–1.45 | Pages, multi-page navigation (`st.navigation`), forms, dialogs, data tables |
| Data | pandas | Tables, CSV import/export, date filtering |
| Charts | Plotly | Donut, stacked activity bars, top-detections bars, type breakdown |
| Chart images | Kaleido 1.x (uses local Chrome/Chromium) | Renders the donut chart into the PDF |
| PDF | fpdf2 | Report generation in memory |
| HTTP | requests | VirusTotal v3, AbuseIPDB v2, ThreatFox, URLhaus and RDAP REST APIs |
| Graph | NumPy + Plotly | Force-directed infrastructure graph (no networkx) |
| Shodan | official `shodan` SDK | Host lookups |
| Storage | SQLite (Python standard library) | Users, settings, scan history, analyst verdicts |
| Security | `hashlib.pbkdf2_hmac`, `hmac.compare_digest` | Password hashing and verification |
| Tests | pytest + Streamlit `AppTest` | Logic tests and headless UI tests |

---

## 2. Project layout

```
threat-intel-aggregator/
├── streamlit_app.py           # Entry point: theme, login gate, navigation
├── views/                     # One file per page
│   ├── dashboard.py
│   ├── analytics.py
│   ├── scan.py
│   ├── investigations.py
│   ├── graph.py
│   ├── verdicts.py
│   ├── reports.py
│   └── settings.py
├── tia/                       # Application package (no Streamlit code outside tia/ui)
│   ├── config.py              # Paths, risk levels and colours
│   ├── ioc.py                 # Refanging, type detection, list parsing
│   ├── sources.py             # VirusTotal, AbuseIPDB, Shodan, ThreatFox, URLhaus, RDAP clients
│   ├── scoring.py             # Source verdict rules
│   ├── threatscore.py         # 0-100 factor score, bands, escalation, verdict override
│   ├── intel.py               # Sightings and change detection
│   ├── extract.py             # IOC extraction from free text
│   ├── export.py              # STIX 2.1 bundle, block list
│   ├── graph.py               # Infrastructure graph model, layout, figure
│   ├── scanner.py             # Runs one scan, flattens results into table rows
│   ├── storage.py             # SQLite store
│   ├── auth.py                # Password hashing, login check, hash CLI
│   ├── charts.py              # Plotly figures
│   ├── report.py              # PDF builder and SMTP email
│   ├── legacy.py              # One-time import of version 1 JSON files
│   └── ui/                    # Streamlit helpers: theme, components, login views
├── assets/logo.svg, logo_wide.svg
├── tests/                     # pytest suite (logic + UI)
├── docs/screenshots/          # README images (synthetic sample data)
├── .streamlit/config.toml     # Dark theme
├── .streamlit/secrets.toml.example
├── requirements.txt / requirements-dev.txt
└── data/                      # Created at runtime: threatintel.db (git-ignored)
```

---

## 3. Architecture

```
Browser ─▶ streamlit_app.py
             ├─ not signed in ─▶ first-run setup (no users yet)  or  login form
             └─ signed in ─────▶ st.navigation ─▶ views/<page>.py
                                                    │
         views/scan.py ─▶ tia.scanner.scan_ioc(raw, keys, store=store)
                              ├─ tia.ioc.normalize      refang + classify
                              ├─ tia.sources.*          VirusTotal (all types),
                              │                         AbuseIPDB + Shodan (public IPs),
                              │                         ThreatFox + URLhaus (abuse.ch key),
                              │                         RDAP (domains, URL hosts)
                              ├─ store.ioc_history ─▶ tia.intel.sightings / diff
                              ├─ store.get_verdict
                              └─ tia.threatscore.assess rule verdict + factor score + override
                                                    │
                              tia.storage.Store ─▶ data/threatintel.db
                                                    │
     dashboard / analytics / investigations / reports read the store
                              ├─ tia.charts  (Plotly)
                              ├─ tia.graph   (infrastructure graph)
                              ├─ tia.report  (fpdf2 PDF, SMTP email)
                              └─ tia.export  (STIX 2.1, block list)
```

Design choices:

- **Logic is separate from the UI.** Everything under `tia/` except `tia/ui/` is plain Python, so it can be unit-tested and reused (for example from a script or another front end).
- **Sources never raise.** Each client returns `{"ok": bool, ...}` with an `error` field or `skipped: True`. One failing source can't break a scan, and failures show up in the result.
- **Results are saved as they come in.** A batch writes each result as soon as it's ready, so stopping halfway keeps what was already scanned.

---

## 4. Risk scoring

| Source | High | Medium | Low | Legitimate |
|---|---|---|---|---|
| VirusTotal: engines flagging as malicious (all types) | ≥ 10 | 4–9 | 1–3 | 0 |
| AbuseIPDB: abuse confidence score (public IPs only) | ≥ 80% | 30–79% | 1–29% | 0% |
| ThreatFox listing | confidence ≥ 50% | < 50% | | |
| URLhaus listing | URL online now | listed, none online | | |

- The source verdict is the **most severe** level among sources that answered. Absence from a feed never sets a level.
- `tia.threatscore` then computes a **0–100 score** from named factors (see the README table): VirusTotal detections (4.5 each, cap 45) and suspicious votes, negative reputation, AbuseIPDB confidence × 0.35 and report volume, whitelisting (−15), risky exposed services (5 each, cap 15), Shodan CVEs (3 each, cap 15), ThreatFox (40), URLhaus (35 online / 20 historic), domain age < 30 / < 180 days (15 / 7), and workspace history (+10 previously High/Medium, +3 seen in ≥ 3 investigations). Bands: ≥ 70 High, ≥ 40 Medium, ≥ 15 Low.
- The score can **raise** severity (the reason says so) but never lowers it. With no reputation source answering, severity stays Unknown.
- An **analyst verdict** (malicious → High, benign → Legitimate) overrides everything and is listed first among the reasons.
- An IP that AbuseIPDB has **whitelisted** has its AbuseIPDB level cancelled. VirusTotal detections still count.
- **Unknown** means no source returned data: missing API keys, rate limits, network errors, or a private/reserved IP address (which public feeds can't know about). Unknown is never counted as clean.
- Each result lists its reasons, for example *"VirusTotal: 14 of 72 engines flag it as malicious"* or *"AbuseIPDB: 100% abuse confidence from 312 reports"*.

### Indicator handling

| Input | Result |
|---|---|
| `hxxp://`, `hxxps[:]//`, `[.]`, `(.)`, `{.}`, `[dot]`, `[/]` | Refanged before lookup (the original input is kept and shown) |
| 32 / 40 / 64 hex characters | MD5 / SHA1 / SHA256 (lower-cased) |
| Valid IPv4 or IPv6 (checked with `ipaddress`) | IP; private and reserved ranges are not sent to external APIs |
| `scheme://...` | URL |
| Valid hostname | Domain (lower-cased) |
| Anything else | Unknown type; still searched on VirusTotal as free text |

---

## 5. Pages

| Page | What you can do |
|---|---|
| **Dashboard** | KPI cards (total, High, Medium, Low, clean/unknown, last 7 days), risk donut, stacked daily activity, the latest 8 indicators |
| **Analytics** | Choose a date range. KPIs (unique indicators, % flagged, IPs, lookup errors), risk donut, daily activity by risk, top 10 VirusTotal detections, indicator types, and a table of High/Medium results |
| **Scan** | Four tabs: **Single indicator** (verdict card with threat score, changes since the last scan, VirusTotal/AbuseIPDB/Shodan cards, score breakdown, threat feeds, context with RDAP and workspace sightings, analyst verdict form, engine detections and raw JSON), **Paste a list**, **Extract from text** (paste or upload text; review extracted IOCs in an editable table, then scan the selection), and **Upload CSV** (guesses the IOC column). Batch options: include Shodan, and free-tier pacing (15 s between lookups). Results can be downloaded as CSV, opened as an investigation, or sent to Reports |
| **Investigations** | Pick a past scan. Filter by risk (pills), type and text. Click a row to see its full details. Download CSV, build a report, delete the investigation, or clear history (with confirmation) |
| **Infrastructure graph** | Indicators (latest result each) linked through shared hosting organisation, ThreatFox malware family, VirusTotal tags, Shodan hostnames and URL hosts. Filters for severity, link types and the minimum number of indicators sharing an attribute. Cluster table ranked by worst severity |
| **Verdicts** | KPIs, add/update a verdict by indicator (defanged accepted), filter by verdict, remove, export as a text list |
| **Reports** | Pick an investigation, set a title, optionally include the chart, then **Generate PDF** and download it. Email it over SMTP (Gmail SSL on 465 by default; STARTTLS for other ports). Download a **STIX 2.1 bundle** or a **block list** for the chosen severities |
| **Settings** | **API keys** (admins only; shows where each key comes from and has a "Test connections" button), **Users** (admins: add users, change roles, reset passwords, delete users), **My account** (change your password), **About** |

### Roles

| | Admin | Analyst |
|---|---|---|
| Scan, investigate, report | ✔ | ✔ |
| See scan history | Everyone's | Own only |
| Change API keys, manage users | ✔ | — |

---

## 6. Installation and running

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
streamlit run streamlit_app.py           # http://localhost:8501
```

1. **First launch:** create the admin account (username plus a password of 8+ characters mixing letters and numbers).
2. **API keys:** go to **Settings → API keys**, paste the keys and click **Test connections**.
3. **Optional, PDF chart:** Kaleido 1.x needs Chrome or Chromium installed. Without it, the PDF is still created, just without the chart.

### Configuration reference

| Setting | How |
|---|---|
| API keys | `[apikeys]` (`VT`, `AbuseIPDB`, `Shodan`, `AbuseCH`) in `.streamlit/secrets.toml` → env vars `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`, `ABUSECH_API_KEY` → Settings page (first found wins). RDAP needs no key |
| Extra users (read-only, e.g. on Streamlit Cloud) | `[credentials] users = [{ username, role, password_hash }]` in secrets |
| Password hash for secrets | `python -m tia.auth` (prompts, then prints `pbkdf2_sha256$...`) |
| Data folder | `TI_DATA_DIR` env var (default `./data`) |
| Theme | `.streamlit/config.toml` |

### Streamlit Community Cloud
Point the app at `streamlit_app.py` and paste your secrets (API keys and a user with a `password_hash`) into **App settings → Secrets**. Cloud storage is temporary, so scan history resets when the app restarts. Use a persistent host if you need to keep history.

### Upgrading from version 1
If `configure.json`, `apikeys.json` or `scan_log.json` from version 1 are in the project folder when the database is first created, they are imported automatically. Passwords are hashed, keys are copied, and scans are re-scored with the new rules. The JSON files are left untouched, so delete them afterwards.

---

## 7. Security notes

- Passwords are stored as salted PBKDF2-SHA256 hashes (260,000 iterations) and compared in constant time. There are no default credentials.
- After 5 failed logins, sign-in is paused for 30 seconds in that browser session.
- Plain-text `password` entries in secrets still work for compatibility, but the sidebar shows a warning until they are replaced with `password_hash`.
- API keys saved on the Settings page are stored unencrypted in `data/threatintel.db`. Protect that folder, or use secrets/environment variables. `data/`, `secrets.toml` and the old JSON files are git-ignored.
- SMTP credentials are used once per send and never stored.

---

## 8. Testing

```bash
pip install -r requirements-dev.txt
pytest
```

Result on 2026-11-17 (Windows 11, Python 3.8.3, Streamlit 1.40.1): **102 passed**.

| Suite | Tests | Covers |
|---|---|---|
| `tests/test_core.py` | 57 | Type detection and refanging; every risk rule including the v1 bug cases; VirusTotal/AbuseIPDB/Shodan parsing with mocked HTTP (success, not found, 401, 429 retry and give-up, network error); scanner (all sources, private IP, no keys, errors); hashing, validation and login; SQLite sessions and per-user scope; legacy import; PDF with Unicode and multiple pages; chart rendering; SMTP |
| `tests/test_intel.py` | 23 | ThreatFox (ip:port matching), URLhaus and RDAP parsing; score factors and caps; escalation without downgrade; whitelist; feed rules; analyst overrides; sightings and diff; history and verdict storage; scanner integration with a store; text extraction against noisy input; STIX 2.1 patterns, escaping and labels; block lists; graph clustering, direct URL-host links and deterministic layout |
| `tests/test_ui.py` | 22 | First-run setup and weak-password rejection; login, failure and lockout; every page (including graph and verdicts) with and without data; single scan; pasted batch; extract-from-text flow; saving a verdict and seeing it override the next scan; verdicts page add/filter/remove; graph page clusters; investigation table; PDF and export downloads; saving keys; adding users; changing password; analyst restrictions |

Streamlit 1.40's `AppTest` doesn't execute pages registered with `st.navigation`, so UI tests run each `views/*.py` page directly with a signed-in session. A test fixture stubs RDAP (which needs no key and would otherwise hit the network) and ignores any real `.streamlit/secrets.toml` on the developer's machine. Full navigation was also checked by hand in headless Chrome, using a seeded sample database. Every page loaded with no errors and no failed network requests, including row selection and PDF generation.

Not covered by automated tests: live calls with real API keys, and sending a real email.

---

## 9. Changelog: version 1 → 2.0

| # | v1 problem | Fix in 2.0 |
|---|---|---|
| 1 | AbuseIPDB thresholds were applied to the *report count* | Thresholds use the *abuse confidence score* |
| 2 | AbuseIPDB confidence 0 (or no AbuseIPDB key) made any IP "Legitimate", even with 40 VirusTotal hits | Verdict is the most severe source; whitelisting only cancels AbuseIPDB |
| 3 | Errors and rate limits were scored as clean | New **Unknown** verdict, errors listed per result, automatic retry on HTTP 429, optional free-tier pacing |
| 4 | Plain-text passwords, default `admin/admin` | PBKDF2 hashing, first-run admin setup, roles, login lockout |
| 5 | Runtime files with keys not git-ignored | Data in git-ignored `data/` SQLite database |
| 6 | Non-Latin characters crashed the PDF | Text is safely converted to Latin-1; fpdf2 replaces abandoned fpdf |
| 7 | New PDF and PNG files written on every Reports visit | PDF built in memory, only when requested |
| 8 | Defanged IOCs not cleaned before lookup | Full refanging |
| 9 | Loose IP regexes (`999.999.999.999` counted as an IP) | `ipaddress` validation; private ranges skipped |
| 10 | No Shodan in batch scans | Optional Shodan toggle for batches |
| 11 | Unpinned requirements, unused package | Version ranges; unused `virustotal-python` removed |
| 12 | One shared JSON file for all users | SQLite with WAL and per-user history |
| — | URL special characters broke VirusTotal queries | Query parameters are URL-encoded |
| — | 880-line single file | `tia/` package + one file per page + tests |
| — | Blocking 2-second splash screen | Removed |

UI redesign: dark theme with Inter font, a sectioned sidebar with icons, KPI cards, a tabbed scan workflow, verdict and source cards, a table where clicking a row shows its details, confirmation dialogs, a redesigned PDF, and a new SVG logo.

---

## 10. Changelog: 2.0 → 2.1 (intelligence features)

| Area | Change |
|---|---|
| Sources | abuse.ch **ThreatFox** (malware family, threat type, confidence) and **URLhaus** (malicious URLs, online count) with one optional key; **RDAP** domain age, registrar and expiry with no key |
| Scoring | `tia.threatscore`: explainable 0–100 score from named factors, severity bands, escalation when evidence adds up, never a downgrade |
| Local intel | `Store.ioc_history` + `tia.intel.sightings`: first/last seen, scan and investigation counts, worst previous severity across the workspace |
| Change detection | `tia.intel.diff`: severity, score, detections, abuse confidence, ports opened/closed, new CVEs, feed listing changes |
| Verdicts | New `verdicts` table; verdict form on every result and a **Verdicts** page; overrides apply to every later scan |
| Extraction | `tia.extract`: defang-aware extraction of URLs, IPs, hashes and domains from free text, with filtering of file names, namespace hosts and private/reserved IPs |
| Graph | `tia.graph` + **Infrastructure graph** page: clusters by shared organisation, malware family, tag, hostname and URL host; NumPy force layout |
| Exports | `tia.export`: STIX 2.1 bundle (deterministic indicator IDs, identity object, score as confidence) and block list |
| UI | Score column in every table, score in the PDF table, risky ports highlighted, "Analyst override" badge, source status shows abuse.ch and RDAP |
| Tests | 73 → 102 |
