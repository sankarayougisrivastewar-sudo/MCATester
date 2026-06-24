# MCATester — AI-Powered OSINT & Vulnerability Discovery Platform

> Built during a security research internship at the National e-Governance Division (NeGD), MeitY, New Delhi.

[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-green)](https://fastapi.tiangolo.com)
[![Groq](https://img.shields.io/badge/AI-Groq%20LLaMA%203.3%2070B-orange)](https://groq.com)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

MCATester is a full-stack OSINT and vulnerability discovery platform that turns passive reconnaissance into **confirmed, zero-false-positive security findings** — with an AI decision layer that makes the scanner adaptive rather than just automated.

---

## The core problem it solves

Most scanners produce noise. Running gobuster + nikto + sqlmap on a real target produces hundreds of raw results requiring hours of manual filtering. MCATester produces clean findings — a SQLi finding means the database actually executed a sleep command, an XSS finding means the payload was reflected unescaped in the HTML response.

**On mca.gov.in (before vs after noise reduction):**

```
First version:  68 findings — 61 false positives (all 403 responses)
Current version: 11 findings — 0 false positives
```

The key insight: 403 responses are ambiguous. A WAF returning 403 on `/admin` doesn't mean admin exists. Content confirmation — checking what the 403 response body actually contains — eliminates this entire class of false positive.

---

## Real findings — Ministry of Corporate Affairs, India

Discovered during authorized research on `mca.gov.in`:

```
CRITICAL  CVE-2023-27997  CVSS 9.8
          vpnv3.mca.gov.in:4111 — Fortinet SSL VPN pre-auth heap overflow
          Unauthenticated remote code execution, no credentials required

CRITICAL  CVE-2022-40684  CVSS 9.8
          Fortinet authentication bypass — full admin access without credentials
          Affected: FortiOS 7.0.0-7.0.6, 7.2.0-7.2.1

CRITICAL  CVE-2018-13379  CVSS 9.1
          Fortinet path traversal — VPN session credentials readable
          via /remote/fgt_lang without authentication

HIGH      Unauthenticated File-Serving API
          pminternship.mca.gov.in/mca-api/files/get-file-by-path
          No auth required to request arbitrary file paths

HIGH      CVE-2023-24486  CVSS 8.8
          GroupWise WebAccess XSS + session hijack
          mail.mca.gov.in — active groupware installation
```

Responsibly disclosed to CERT-In (`incident@cert-in.org.in`) with full PDF report.

---

## Confirmed findings on demo.testfire.net (deliberately vulnerable lab)

```
CRITICAL  SQL Injection — Time-based blind (PostgreSQL confirmed)
          URL    : http://demo.testfire.net/search.jsp
          Payload: '; SELECT pg_sleep(3)--
          Evidence: 3.8s response vs 0.6s baseline

CRITICAL  Swagger/OpenAPI UI exposed publicly
          URL    : http://demo.testfire.net/swagger/properties.json
          Email leaked: jsmtih@altoromutual.com

HIGH      Reflected XSS
          URL    : http://demo.testfire.net/search.jsp
          Payload: <mcatest123> reflected unescaped in HTML response

[AI-Agent] Risk: CRITICAL (score: 9.5/10)
[AI-Agent] → Remove public Swagger access
[AI-Agent] → Patch CVE-2025-24813 (Tomcat partial PUT RCE, CVSS 9.8)
[AI-Agent] → Fix SQLi with parameterized queries
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     MCATester — 16 Stage Pipeline               │
│                                                                 │
│  Stage 1   DNS + Whois + Subdomain Enum (crt.sh/VT/HT)        │
│  Stage 2   Recursive Asset Discovery (parallel, 20 threads)    │
│  Stage 3   Subdomain Takeover Detection (20 services)          │
│  Stage 4   Threat Intel (urlscan / AbuseIPDB / OTX)           │
│  Stage 5   Tech Stack Detection (WhatWeb + headers)            │
│  Stage 6   AI Context Injector — Gemini generates dork queries │
│  Stage 7   Google Dorking (20+ categories, DDG + Serper)       │
│  Stage 8   Fetch + Content Confirmation (35 patterns)          │
│  Stage 9   Active Probing + WAF Detection                      │
│  Stage 10  Attack Chain Orchestrator                           │
│  Stage 11  Header Security Analysis                            │
│  Stage 12  Payload Injection (SQLi / XSS / Traversal)         │
│  Stage 13  CVE Correlation + NVD Enrichment                   │
│  Stage 14  AI Decision Engine (Groq) ← 5 decision points      │
│  Stage 15  Gemini Report Generation                            │
│  Stage 16  PDF Export + Webhook Alerts                         │
│                                                                 │
│  FastAPI backend + SQLite + Real-time dashboard                 │
└─────────────────────────────────────────────────────────────────┘
```

The AI Decision Engine (Stage 14) is not just report-writing — it makes actual decisions at 5 points: target triage, URL prioritization, injection targeting, CVE exploitability assessment, and final risk ranking.

---

## How MCATester compares

| Capability | MCATester | Nikto | gobuster | Burp Suite Free |
|---|:---:|:---:|:---:|:---:|
| Zero false positives | ✓ | ✗ | ✗ | Manual |
| CVE correlation | ✓ | Partial | ✗ | ✗ |
| SQLi/XSS confirmation | ✓ | ✗ | ✗ | Manual |
| Subdomain takeover | ✓ | ✗ | ✗ | ✗ |
| AI risk scoring | ✓ | ✗ | ✗ | ✗ |
| Attack chain orchestration | ✓ | ✗ | ✗ | Manual |
| Real-time dashboard | ✓ | ✗ | ✗ | ✓ |
| PDF report | ✓ | ✗ | ✗ | Pro only |
| Drift detection | ✓ | ✗ | ✗ | ✗ |
| Webhook alerts | ✓ | ✗ | ✗ | ✗ |

---

## Features

### Passive Recon
- DNS (A/MX/NS/TXT/SOA/Reverse), Whois
- Subdomain enumeration — VirusTotal, crt.sh, HackerTarget, sublist3r (45+ subdomains found on real targets)
- GitHub recon — repositories referencing the target
- Threat intelligence — urlscan.io, AbuseIPDB, OTX AlienVault
- Email discovery + Holehe registration checking (400+ sites)
- IP intelligence — ASN, ISP, geolocation

### Active Discovery
- Parallel recursive asset scanning (28 assets in 3 min)
- WhatWeb tech stack fingerprinting
- 66+ path probes with WAF detection
- AI-targeted probing — Gemini generates paths specific to detected tech stack
- Subdomain takeover detection (20 services: GitHub Pages, Heroku, Netlify, Vercel, AWS S3, Azure, Shopify, HubSpot, Zendesk...)

### Vulnerability Confirmation
- **SQL Injection** — error-based + time-based blind, auto-detects MySQL/MSSQL/PostgreSQL
- **Reflected XSS** — safe payload reflection detection
- **Path Traversal** — file API parameter testing with content confirmation
- **WAF pre-check** — if WAF blocks all pages, skip injection (saves ~3 min on hardened targets)
- **Content Confirmation** — 35 signatures, kills 403 false positives

### Attack Chain Orchestrator
When one finding is confirmed, automatically fires follow-up probes:
- Swagger found → probe 12 API endpoints
- VPN login found → probe Fortinet-specific paths
- File API found → test 10 traversal payloads (deduplicated by base endpoint)
- Webmail found → probe 7 credential paths

### CVE Intelligence
- Static knowledge base — Fortinet, Lotus Domino, GroupWise, Tomcat, Apache, nginx, WordPress, PHP
- NVD API enrichment for confirmed CVEs
- Auto-matches detected tech stack to CVE database
- AI exploitability assessment with confidence levels

### AI Decision Engine (Groq)
5 real decisions per scan — not just report formatting:

```
Decision 1: Target triage
  → Classifies as government/enterprise/SaaS
  → Identifies high-value subdomains to prioritize

Decision 2: URL ranking
  → Ranks 40+ discovered URLs by exploitation potential
  → VPN login page > generic content page

Decision 3: Injection targeting
  → Selects which pages are worth injection testing
  → Skips pages with no injectable parameters

Decision 4: CVE exploitability
  → Assesses if correlated CVEs are likely exploitable
  → Considers service accessibility + version ranges

Decision 5: Final risk assessment
  → Risk score (0-10)
  → Executive summary (2-3 sentences for management)
  → Technical summary (attack vectors for security team)
  → Specific immediate actions
```

### Dashboard & Reporting
- Real-time web dashboard — live scan status, severity donut, risk trend chart
- Attack Chains page — findings grouped by CVE Intelligence / Active Exploitation / Infrastructure
- Alerts page — all CRITICAL/HIGH findings across all scans, grouped by target with timestamps
- Drift detection — scan-over-scan comparison, flags new/resolved/changed findings
- PDF report — VAPT-style with findings, evidence, CVSS scores, remediation steps
- Webhooks — Slack, Discord, Telegram for HIGH+ findings

---

## Installation

**Requirements:** Python 3.10+, Linux or WSL2, nmap

```bash
git clone https://github.com/yourusername/MCATester.git
cd MCATester

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Optional but improves results significantly
pip install groq
sudo apt install nmap whatweb
```

### API Keys (`.env`)

```bash
cp .env.example .env
# Edit .env with your keys
```

| Key | Where to get | Cost |
|---|---|---|
| `GEMINI_API_KEY` | aistudio.google.com | Free (15 req/min) |
| `SERPER_API_KEY` | serper.dev | Free (2500/month) |
| `VIRUSTOTAL_API_KEY` | virustotal.com | Free (500/day) |
| `GROQ_API_KEY` | console.groq.com | Free (fast) |
| `SHODAN_API_KEY` | shodan.io | $49/year |

---

## Usage

### CLI

```bash
# Full scan — all 16 stages
python osint_agent.py mca.gov.in

# Passive only — no active probing or injection
python osint_agent.py mca.gov.in --passive

# Skip recursive discovery (faster — ~5 min vs ~10 min)
python osint_agent.py mca.gov.in --no-recursive
```

### Dashboard

```bash
python server.py
# Open http://localhost:8000
```

Enter domain → Start Scan → watch results populate in real time.

---

## Scan performance

```
mca.gov.in (45 subdomains, WAF protected):
  Total time    : ~10 minutes
  Findings      : 11 (zero false positives)
  False positives: 0 (was 61 in v1)

demo.testfire.net (no WAF, vulnerable):
  Total time    : ~12 minutes
  Findings      : 15 (confirmed SQLi + XSS + CVEs)

Time breakdown (approximate):
  Subdomain enum        : 2 min  (crt.sh + VirusTotal sequential)
  Recursive discovery   : 3 min  (28 assets parallel)
  Dorking               : 2 min  (DDG + Serper)
  Payload injection     : 0 min  (WAF pre-check skips on mca.gov.in)
                          3 min  (full testing on demo.testfire.net)
  CVE + AI decisions    : 1 min  (5 Groq calls)
  Other stages          : 2 min
```

---

## Project structure

```
MCATester/
├── osint_agent.py           # Main pipeline — 16 stages, CLI entry
├── server.py                # FastAPI backend — scan management + API
├── orchestrator.py          # Attack chain engine
├── ai_decision_engine.py    # Groq LLM — 5 decision points per scan
├── ai_context_injector.py   # Gemini — targeted dork + path generation
├── cve_correlation.py       # CVE matching + NVD API enrichment
├── payload_injector.py      # SQLi/XSS/traversal with WAF pre-check
├── subdomain_takeover.py    # Dangling CNAME — 20 services
├── recursive_discovery.py   # Parallel subdomain + port scanner
├── delta_detection.py       # Scan-over-scan diff
├── content_confirmation.py  # 35-pattern false-positive eliminator
├── webhooks.py              # Slack/Discord/Telegram alerts
├── osint_features.py        # PDF report generator
├── osint_identity.py        # IP intel + Holehe
├── search.py                # DDG/Serper wrapper
├── static/
│   └── index.html           # Real-time dashboard SPA
├── requirements.txt
├── .env.example
└── README.md
```

---

## Responsible use

**Only test systems you own or have explicit written permission to test.**

Built-in safety measures:
- Warning banner on every CLI run
- `--passive` mode disables all active testing
- Injection payloads are read-only diagnostics — no write operations
- Rate limiting (1s between requests)
- WAF pre-check skips injection when target is hardened
- 403 responses never reported as findings

For disclosures: India → CERT-In `incident@cert-in.org.in`

---

## Tech stack

| Layer | Technology |
|---|---|
| Pipeline | Python 3.12 |
| Backend API | FastAPI + SQLite |
| Frontend | Vanilla JS + CSS custom properties |
| AI decisions | Groq — llama-3.3-70b-versatile |
| AI context | Google Gemini 2.5 Flash |
| PDF generation | ReportLab |
| Port scanning | Shodan InternetDB + nmap fallback |
| Tech detection | WhatWeb + header inference |
| Subdomain data | crt.sh + VirusTotal + HackerTarget |

---

## Roadmap

- [ ] Screenshot capture — Playwright screenshots of all discovered assets
- [ ] Scheduled scanning — 24h autonomous monitoring with drift alerts
- [ ] nuclei integration — template-based CVE confirmation
- [ ] Multi-target mode — scan an entire organization at once
- [ ] SARIF export — GitHub Security tab integration

---

## Author

**SANKARAYOUGI SRIVASTESWAR** — B.Tech Computer Science,Security research intern, National e-Governance Division (NeGD), MeitY, New Delhi

---

*For authorized security testing and research only. The author is not responsible for misuse.*
