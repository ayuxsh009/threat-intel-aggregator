<div align="center">

<img src="assets/logo.svg" width="96" alt="Threat Intel Aggregator logo"/>

# Threat Intel Aggregator

**Check IPs, domains, URLs and file hashes against VirusTotal, AbuseIPDB and Shodan in one place. Get a clear risk verdict, keep a searchable history and export PDF reports.**

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF4B4B?logo=streamlit&logoColor=white)
![SQLite](https://img.shields.io/badge/Storage-SQLite-003B57?logo=sqlite&logoColor=white)
![Plotly](https://img.shields.io/badge/Charts-Plotly-3F4F75?logo=plotly&logoColor=white)
![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)

![Dashboard](docs/screenshots/dashboard.png)

</div>

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Features](#features)
- [Screenshots](#screenshots)
- [How it works](#how-it-works)
- [Risk scoring](#risk-scoring)
- [Tech stack](#tech-stack)
- [Getting started](#getting-started)
- [Getting API keys](#getting-api-keys)
- [Configuration](#configuration)
- [Usage guide](#usage-guide)
- [Users and roles](#users-and-roles)
- [Deployment](#deployment)
- [Project structure](#project-structure)
- [Running the tests](#running-the-tests)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## Why this exists

When an alert fires, an analyst usually opens three browser tabs, pastes the same indicator into VirusTotal, AbuseIPDB and Shodan, then tries to combine what they see into one judgement. Threat Intel Aggregator does that in one step:

- **One input, three sources.** Results appear side by side.
- **One verdict.** Each indicator gets a single risk level, with the reasons behind it.
- **Nothing gets lost.** Every scan is saved as an investigation you can search, chart and report on later.

It's built for SOC analysts, incident responders, students learning threat intelligence, and anyone who triages suspicious indicators.

---

## Features

### Scanning
- **Single, list or CSV.** Scan one indicator, paste a list, or upload a CSV. The app guesses which column holds the indicators.
- **Detects the type automatically.** Recognises IPv4/IPv6, domains, URLs, and MD5, SHA1 and SHA256 hashes.
- **Cleans up defanged input.** `hxxp://evil[.]com`, `1.2.3[.]4`, `bad(.)site` and `[dot]` are converted back before lookup, and your original input is kept.
- **Removes duplicates.** Repeated indicators in a list are scanned once.
- **Skips private IPs.** RFC 1918 and other reserved addresses aren't sent to external APIs, which saves quota.
- **Handles rate limits.** It retries when an API answers HTTP 429. An optional **free-tier pacing** mode waits 15 seconds between lookups to stay within VirusTotal's free limit.
- **Saves as it goes.** Each result is stored the moment it's ready, so stopping a batch halfway keeps the work already done.

### Results
- **Verdict card.** A risk badge, the reasons in plain language (for example "VirusTotal: 14 of 72 engines flag it as malicious"), notes, and any lookup errors.
- **One card per source:**
  - **VirusTotal:** detection ratio bar, suspicious/harmless/undetected counts, reputation, tags, and the list of engines that flagged it.
  - **AbuseIPDB:** abuse confidence bar, number of reports and reporters, whitelist status, country, ISP and usage type.
  - **Shodan:** open ports, organisation, operating system, country, hostnames and known CVEs.
- **Raw JSON** from every source, plus a direct link to each provider's page for that indicator.

### Investigations and analytics
- **Investigations.** Every scan is saved. Filter by risk, type or free text, click any row to see its full details, export to CSV, or delete it.
- **Dashboard.** KPI cards, risk distribution, daily activity, and your latest indicators.
- **Analytics.** Pick any date range to see the risk mix, daily activity by risk, the top 10 most-detected indicators, the indicator types, and a list of everything High or Medium risk.

### Reporting
- **PDF reports.** Each report has a branded header, summary tiles, a risk chart, key findings with reasons, the full indicator table, and a section listing lookup problems. It handles any number of rows across pages.
- **Email delivery.** Send the PDF through Gmail (with an App Password) or any SMTP server.
- **CSV export** of any batch or investigation.

### Accounts and security
- **No default password.** On first launch you create the administrator account.
- **Hashed passwords.** Salted PBKDF2-SHA256 with 260,000 iterations, checked in constant time.
- **Roles.** Admins manage API keys and users and see every user's history. Analysts scan and see only their own work.
- **Login lockout.** After 5 failed attempts, sign-in is paused for 30 seconds.
- **Keys from secrets or environment variables**, so they never need to be stored in the database.

---

## Screenshots

> All screenshots use synthetic sample data (documentation IP ranges and `.example` domains).

| Login | Scan |
|---|---|
| ![Login](docs/screenshots/login.png) | ![Scan](docs/screenshots/scan.png) |

| Investigation with indicator detail | Analytics |
|---|---|
| ![Investigations](docs/screenshots/investigations.png) | ![Analytics](docs/screenshots/analytics.png) |

| Reports | PDF output |
|---|---|
| ![Reports](docs/screenshots/reports.png) | ![PDF report](docs/screenshots/pdf_report.png) |

| User management |
|---|
| ![Settings](docs/screenshots/settings.png) |

---

## How it works

```
                    ┌──────────────────────────┐
  Browser  ───────▶ │  streamlit_app.py        │  theme · login gate · navigation
                    └────────────┬─────────────┘
                                 │
        ┌────────────┬───────────┼────────────┬─────────────┬───────────┐
        ▼            ▼           ▼            ▼             ▼           ▼
    Dashboard    Analytics     Scan    Investigations    Reports    Settings
                                 │
                                 ▼
                   tia.scanner.scan_ioc(indicator)
                      │
                      ├─ tia.ioc        refang → classify → normalise
                      ├─ tia.sources    VirusTotal (every type)
                      │                 AbuseIPDB + Shodan (public IPs)
                      └─ tia.scoring    most severe level, or Unknown
                                 │
                                 ▼
                   tia.storage  ──▶  data/threatintel.db (SQLite, WAL)
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
          tia.charts (Plotly)           tia.report (fpdf2 PDF, SMTP)
```

- All application logic lives in the `tia/` package as plain Python, separate from the UI. That makes it easy to test and reuse from scripts.
- The source clients never raise exceptions. Each returns `{"ok": ..., "error": ...}`, so one failing API can't break a scan.
- SQLite in WAL mode lets several browser sessions read and write at the same time safely.

---

## Risk scoring

Each source produces its own level, and the indicator takes **the most severe one**.

| Source | 🔴 High | 🟠 Medium | 🟡 Low | 🟢 Legitimate |
|---|---|---|---|---|
| **VirusTotal**: engines flagging as malicious (all types) | ≥ 10 | 4 – 9 | 1 – 3 | 0 |
| **AbuseIPDB**: abuse confidence score (public IPs only) | ≥ 80 % | 30 – 79 % | 1 – 29 % | 0 % |

- ⚪ **Unknown** means no source returned data: missing keys, rate limits, network errors, or a private IP. **Unknown is never treated as clean.**
- If AbuseIPDB has **whitelisted** an IP, its AbuseIPDB level is cancelled, but VirusTotal detections still count.
- Every verdict comes with the reasons behind it, so analysts can see why a score was given.

---

## Tech stack

| Layer | Technology |
|---|---|
| Language | Python 3.8+ |
| Web UI | [Streamlit](https://streamlit.io) (multi-page `st.navigation`, dialogs, interactive tables) |
| Data | pandas |
| Charts | Plotly (+ Kaleido for chart images in the PDF) |
| PDF | fpdf2 |
| HTTP / APIs | requests, official `shodan` SDK |
| Storage | SQLite (standard library) |
| Auth | PBKDF2-SHA256 via `hashlib` (standard library) |
| Testing | pytest, Streamlit `AppTest` |

---

## Getting started

### Prerequisites

- **Python 3.8 or newer** ([download](https://www.python.org/downloads/))
- **Git**
- *Optional:* **Google Chrome or Chromium**, so the risk chart can be embedded in PDF reports. Without it, reports are still created, just without the chart.

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/ayuxsh009/threat-intel-aggregator.git
cd threat-intel-aggregator

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows (PowerShell):  .venv\Scripts\Activate.ps1
# Windows (cmd):         .venv\Scripts\activate.bat
# macOS / Linux:         source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the app
streamlit run streamlit_app.py
```

Open **http://localhost:8501**.

### First launch

1. The **Set up your workspace** screen appears. Create the administrator account (password of at least 8 characters, mixing letters and numbers).
2. You're signed in automatically.
3. Go to **Settings → API keys**, paste your keys, click **Save keys**, then **Test connections**.

---

## Getting API keys

All three services have free plans.

| Service | Sign up | Where to find the key | Used for |
|---|---|---|---|
| **VirusTotal** | [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) | Profile menu → **API key** | Every indicator type |
| **AbuseIPDB** | [abuseipdb.com/register](https://www.abuseipdb.com/register) | **Account → API → Create Key** | IP addresses |
| **Shodan** | [account.shodan.io/register](https://account.shodan.io/register) | Shown on your [account page](https://account.shodan.io) | IP addresses (optional) |

> **Tip:** VirusTotal is the most important key. It's the only source for domains, URLs and hashes. Free keys allow about 4 lookups per minute, so turn on **free-tier pacing** for large batches.

---

## Configuration

### API keys

Keys are looked up in this order; the first one found is used:

1. **Streamlit secrets:** `.streamlit/secrets.toml`
2. **Environment variables:** `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `SHODAN_API_KEY`
3. **Settings page:** stored in the local database

The Settings page shows where each active key comes from. Keys set by secrets or environment variables are read-only in the UI.

### Secrets file

Copy the template and fill it in:

```bash
cp .streamlit/secrets.toml.example .streamlit/secrets.toml
```

```toml
[apikeys]
VT = "your_virustotal_api_key"
AbuseIPDB = "your_abuseipdb_api_key"
Shodan = "your_shodan_api_key"

# Optional: users defined outside the database (useful on Streamlit Cloud)
[credentials]
users = [
  { username = "analyst", role = "admin", password_hash = "pbkdf2_sha256$260000$..." },
]
```

Generate a password hash with:

```bash
python -m tia.auth
```

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `VT_API_KEY` | VirusTotal key | — |
| `ABUSEIPDB_API_KEY` | AbuseIPDB key | — |
| `SHODAN_API_KEY` | Shodan key | — |
| `TI_DATA_DIR` | Folder for the SQLite database | `./data` |

### Theme

Colours and fonts are set in `.streamlit/config.toml` (dark theme by default).

---

## Usage guide

### Scan a single indicator
1. Open **Scan → Single indicator**.
2. Enter an IP, domain, URL or hash. Defanged input is fine.
3. Click **Scan**. You'll see the verdict card, the three source cards, the detecting engines and the raw data.

> Safe test values: `8.8.8.8` (Google DNS, should be clean) and `44d88612fea8a8f36de82e1278abb02f` (the harmless EICAR antivirus test file, flagged by most engines).

### Scan a list
1. Open **Scan → Paste a list**.
2. Paste indicators separated by new lines, commas or spaces.
3. Choose whether to **include Shodan for IPs** and whether to use **free-tier pacing**.
4. Click **Scan list**, then download the CSV, open the investigation, or build a report.

### Scan a CSV file
1. Open **Scan → Upload CSV**.
2. Upload the file. A column named `ioc`, `indicator`, `ip`, `domain`, `url` or `hash` is selected automatically, or you can pick one.
3. Click **Start batch scan**.

Example file:

```csv
ioc,source
8.8.8.8,firewall
example[.]com,email
44d88612fea8a8f36de82e1278abb02f,edr
```

### Review investigations
**Investigations** lists every scan session. Choose one, filter by risk, type or text, and **click a row** to see its full details. You can download a CSV, build a report, delete the investigation, or clear all history (with confirmation).

### Build a report
1. Open **Reports** and pick an investigation.
2. Set a title, and choose whether to include the risk chart.
3. Click **Generate PDF**, then **Download PDF**.
4. *Optional:* to email it, enter the recipient, the sender address and an app password. Gmail is the default; other providers can be set under **SMTP server**.

> For Gmail, create an **App Password** under Google Account → Security → 2-Step Verification → App passwords. Your normal password won't work.

---

## Users and roles

| Capability | Admin | Analyst |
|---|:---:|:---:|
| Scan, investigate, analytics, reports | ✅ | ✅ |
| Scan history visible | Everyone's | Own only |
| Change API keys | ✅ | ❌ |
| Add / edit / delete users, reset passwords | ✅ | ❌ |
| Change own password | ✅ | ✅ |

Manage users under **Settings → Users**.

---

## Deployment

### Local or internal server
```bash
streamlit run streamlit_app.py --server.port 8501 --server.headless true
```
To keep scan history long term, put the `data/` folder (or `TI_DATA_DIR`) on persistent storage and back it up.

### Streamlit Community Cloud
1. Fork or push this repository to your GitHub account.
2. At [share.streamlit.io](https://share.streamlit.io), create an app pointing at `streamlit_app.py`.
3. Under **App settings → Secrets**, paste your `[apikeys]` and at least one `[credentials]` user with a `password_hash`.

> Cloud storage is temporary: the database resets when the app restarts. Use a host with a persistent disk if you need to keep history.

### Upgrading from version 1
If version 1's `configure.json`, `apikeys.json` or `scan_log.json` are in the project folder when the database is first created, they're imported automatically. Passwords are hashed, keys are copied, and old scans are re-scored with the current rules. Delete the JSON files afterwards.

---

## Project structure

```
threat-intel-aggregator/
├── streamlit_app.py            # Entry point: theme, login gate, navigation
├── views/                      # One file per page
│   ├── dashboard.py
│   ├── analytics.py
│   ├── scan.py
│   ├── investigations.py
│   ├── reports.py
│   └── settings.py
├── tia/                        # Application package
│   ├── config.py               # Paths, risk levels, colours
│   ├── ioc.py                  # Refanging, type detection, list parsing
│   ├── sources.py              # VirusTotal / AbuseIPDB / Shodan clients
│   ├── scoring.py              # Risk rules
│   ├── scanner.py              # Scan orchestration, table flattening
│   ├── storage.py              # SQLite persistence
│   ├── auth.py                 # Password hashing, login, hash CLI
│   ├── charts.py               # Plotly figures
│   ├── report.py               # PDF builder, SMTP email
│   ├── legacy.py               # Version 1 data import
│   └── ui/                     # Theme, shared components, login screens
├── assets/                     # SVG logos
├── docs/screenshots/           # README images
├── tests/                      # pytest suite
├── .streamlit/
│   ├── config.toml             # Theme
│   └── secrets.toml.example    # Secrets template
├── requirements.txt
├── requirements-dev.txt
└── DOCUMENTATION.md            # In-depth technical documentation
```

---

## Running the tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite has **73 tests**:

- **Core logic (57):** type detection and refanging, every risk rule, the API clients against mocked HTTP (success, not found, invalid key, rate-limit retry, network failure), the scanner, password hashing and login, the database, the version 1 import, and PDF generation including Unicode and multi-page reports.
- **UI (16):** first-run setup, login and lockout, every page with and without data, single and batch scans, the investigation table, PDF generation, API key and user management, password change, and analyst restrictions.

The tests never call the real APIs, so no API keys are needed to run them.

---

## Security

- **Never commit** `.streamlit/secrets.toml` or the `data/` folder. Both are git-ignored.
- API keys saved on the Settings page are stored **unencrypted** in `data/threatintel.db`. On shared machines, use secrets or environment variables instead, and restrict access to that folder.
- Plain-text passwords in secrets still work for compatibility, but the sidebar warns until they're replaced with a `password_hash`.
- SMTP passwords are used once per send and never stored.
- Run the app behind HTTPS (a reverse proxy or Streamlit Cloud) if it's reachable from outside your network.

Found a vulnerability? Please open a private security advisory on GitHub rather than a public issue.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Every result is **Unknown** | No API keys are set, or they're invalid. Go to **Settings → API keys → Test connections**. |
| `VirusTotal rate limit reached (HTTP 429)` | Free keys allow about 4 lookups per minute. Turn on **free-tier pacing** or wait a minute. |
| `rejected the API key (HTTP 401/403)` | The key is wrong or revoked. Copy it again from the provider's site. |
| Shodan shows `Access denied` | Free Shodan accounts have limited host access. Leave the key empty or upgrade. |
| PDF has no chart | Kaleido needs Chrome or Chromium. Install one and generate the report again. |
| Email fails with an authentication error | Use a Gmail **App Password**, not your account password, and check the SMTP host and port. |
| Forgot the admin password | Another admin can reset it under **Settings → Users**. If you're the only admin, stop the app, delete `data/threatintel.db` (this erases all history), and set up again. |
| Streamlit asks for an email in the terminal | Just press Enter, or start it with `streamlit run streamlit_app.py --server.headless true`. |
| Port 8501 already in use | `streamlit run streamlit_app.py --server.port 8502` |

---

## Roadmap

- [ ] More sources (URLhaus, AlienVault OTX, GreyNoise)
- [ ] Scheduled re-scans and alerts when a verdict changes
- [ ] STIX 2.1 and MISP export
- [ ] Encrypted storage for API keys
- [ ] Docker image
- [ ] Light theme toggle

---

## Contributing

Contributions are welcome.

1. Fork the repository and create a branch: `git checkout -b feature/my-change`
2. Install the dev dependencies: `pip install -r requirements-dev.txt`
3. Make your change and add tests.
4. Run `pytest` and make sure everything passes.
5. Open a pull request describing what changed and why.

Please keep logic in `tia/` (free of Streamlit code) and UI in `views/` and `tia/ui/`.

---

## Disclaimer

This tool is for **defensive security, research and education**. Verdicts depend on third-party feeds and can miss new or targeted threats. Treat a result as a starting point for analysis, not a final judgement. Follow each provider's terms of service and API limits.

For architecture details, every page explained, and the version 1 → 2 changelog, see **[DOCUMENTATION.md](DOCUMENTATION.md)**.
