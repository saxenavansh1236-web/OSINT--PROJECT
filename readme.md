# ⬡ OSINT Platform

A self-hosted Open Source Intelligence platform built with Flask. Scan domains, IPs, emails, phone numbers, and usernames; run a full image forensics/intelligence suite on uploaded photos; investigate cases with AI-assisted summaries, entity graphing, cross-case correlation, and IOC export — all from a dark-themed web UI, protected by four layers of built-in security and a public account gate.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.x-black?style=flat-square&logo=flask)
![SQLite](https://img.shields.io/badge/Database-SQLite%20%7C%20PostgreSQL-blue?style=flat-square&logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Security](https://img.shields.io/badge/Security-4%20Layers-red?style=flat-square&logo=shield)

---

## Architecture

```
                        ┌─────────────────┐
                        │      User        │
                        └────────┬────────┘
                                 │ HTTP
                        ┌────────▼────────┐
                        │   Flask App      │
                        │  (app.py)        │
                        │  Rate Limiter    │
                        │  CAPTCHA + Auth  │
                        │  User Login Gate │
                        └────────┬────────┘
                                 │
      ┌───────────────┬──────────┼──────────────┬───────────────┬─────────────────┐
      │               │          │              │               │                 │
┌─────▼──────┐ ┌───────▼──────┐ ┌▼─────────────┐ ┌───▼───────┐ ┌─────▼──────┐ ┌────────▼────────┐
│OSINT Modules│ │ Admin Panel  │ │Image Intel   │ │Case Mgmt  │ │Intelligence│ │  Scan Cache     │
│(40+ modules)│ │ Dashboard    │ │Suite (20+    │ │Evidence   │ │Confidence/ │ │(in-memory /     │
│             │ │Cases/Reports │ │features)     │ │Timeline   │ │Risk/Similar│ │ Redis optional) │
└─────┬──────┘ └───────┬──────┘ └────┬─────────┘ └────┬──────┘ └─────┬──────┘ └─────────────────┘
      │                │             │             │              │
      │                └─────────────┼─────────────┴──────────────┘
      │                              │
┌─────▼──────────────────────────────▼────┐
│              External APIs                │
│  VirusTotal · AbuseIPDB · URLScan         │
│  OTX · HaveIBeenPwned · Wayback           │
└────────────────────┬──────────────────────┘
                      │
             ┌────────▼────────┐
             │  SQLite / Postgres│
             │  History · Users  │
             │  AuditLog · Cases │
             └────────┬─────────┘
                      │
             ┌────────▼─────────────────────────┐
             │  Dashboard + PDF Reports +         │
             │  Investigation Graph +             │
             │  Risk Score + Identity Score +      │
             │  AI Investigation Summary +          │
             │  Related Entities + Social Search +   │
             │  IOC Export (STIX / MISP)              │
             └───────────────────────────────────┘
```

---

## Screenshots

| Scanner | Dashboard |
|---------|-----------|
| ![Scan](docs/scan.png) | ![Dashboard](docs/dashboard.png) |

| Investigation Graph | Risk Score / Identity Score |
|------------|------------|
| ![Graph](docs/graph.png) | ![Risk](docs/risk_score.png) |

| PDF Report | Case Management |
|------------|------------|
| ![Report](docs/report.png) | ![Cases](docs/cases.png) |

| Image Intelligence Suite | Threat Intel Grid (VT / AbuseIPDB / URLScan / OTX) |
|-------------|------------------------------|
| ![Image OSINT](docs/image_osint.png) | ![Threat Intel](docs/threat_intel.png) |

> Add your screenshots to a `docs/` folder and update the paths above.

---

## What's New

- **Public Account System** — the Scanner (`/`) and Image OSINT (`/image-osint`) are now gated behind a lightweight, self-serve user login (`/register`, `/login`, `/logout-user`). This is separate from the admin session used for the dashboard/cases/reports. Every scan is now tied to a session that must first authenticate as a registered user.
- CAPTCHA now also protects registration and login, not just the admin panel and scan form.
- Every account action (register, login, failed login, logout) is written to the audit log.

---

## Features

### Access Control
- **Public User Accounts** — self-service registration (`/register`) and login (`/login`) gate the Scanner and Image OSINT pages. Passwords are hashed; a CAPTCHA is required on both forms.
- **Admin Session** — a fully separate `/admin` login controls the dashboard, case management, reports, scheduled scans, alerts, and user/role administration. Logging into the scanner as a regular user does **not** grant admin access, and vice versa.

### Domain / URL Scanning
- WHOIS, DNS records (A/AAAA/MX/NS/SPF/DMARC), zone-transfer exposure check
- SSL certificate inspection (validity, SAN domains, cipher suite, self-signed detection)
- **Certificate History** — CT-log backed issuer history, wildcard/expired cert counts, subdomains discovered via CT logs
- Subdomain enumeration & reverse IP lookup
- Technology stack detection (CMS, server, framework, CDN, analytics, e-commerce, hosting, JS libs, fonts, marketing tags) + security header flags (HSTS/CSP/X-Frame/X-Content-Type)
- **HTTP Headers Analysis** — A–F security grade, present/missing headers by severity, info-leak detection, cookie flag issues
- **Port Scan** — common port sweep with service/banner detection and risk flags
- **Directory Discovery** — common-path brute force with sensitive-path tagging, tabbed All/Sensitive view
- **Robots & Paths** — robots.txt / sitemap / security.txt parsing, sensitive path detection
- **Cloud Provider Detection** — AWS/GCP/Azure/etc. with confidence level, detection method, CDN/proxy flags
- **Employee Intel** — GitHub org members, email pattern guessing, generic address discovery, social profile links
- Wayback Machine / archive lookup (first/last seen, snapshots by year)
- Screenshot capture with watermarking

### Threat Intelligence Grid
- **VirusTotal** — malicious/suspicious/harmless/undetected engine breakdown, threat names, categories, AS/country info
- **AbuseIPDB** — abuse confidence score, Tor exit detection, whitelist status, report history, hostnames
- **URLScan.io** — verdict, score, page metadata, contacted domains/IPs, detected technologies, screenshot link
- **AlienVault OTX** — pulse count, malware families, adversaries, tags, passive DNS, recent threat pulses
- **Dark Web Monitor** — flags threats and mentions with a 0–100 threat score
- **Paste Monitor** — target mentions across paste sites, severity-tiered (critical/high/medium/low) with snippets and keyword tags
- **Google Dork Generator** — categorized dorks (sensitive files, directories, mentions, tech) with one-click search links

### Email Intelligence
- Breach detection (HaveIBeenPwned & other sources)
- Full email OSINT: format validation, disposable-address detection, MX check, reputation score, flags
- DNS lookup on the domain part

### Phone Intelligence
- Carrier, region, line type (mobile/landline/VOIP/unknown), and timezone via `phonenumbers`
- Confidence-scored validity with a visual bar
- Phone-specific **risk score** (validity, line type, region, carrier, timezone coverage)
- **Cross-correlation** against usernames and breach/leak data tied to the same number
- **Scam / Fraud Intelligence** — fraud score, spam reports, robocall reports, last-reported date; honestly labeled `PROVIDER DATA` (with `SPAM_API_KEY`) or `HEURISTIC ESTIMATE` otherwise
- **VOIP / Virtual Number Check** — confidence-scored VOIP detection against known provider ranges
- **Porting History** — reports carrier porting status when available
- **Business Directory** — only renders when a real, sourced match exists
- **Reverse Phone OSINT** — categorized, clearly-labeled public-mention search suggestion links
- Per-target **Investigation Summary** paragraphs with a transparent confidence rating

### Username Intelligence
- Cross-platform presence search using real verification signals (404 checks, error-string matching, title matching), grouped by category (Social, Video, Dev, Gaming, Creative, Professional, Forums)

### Universal
- **Breach Check** — known data-breach exposure
- **Leak Checker** — multi-source leak search across email, domain, phone, and username
- **Risk Score** — 0–100 composite score with top risk factors (severity, points, category, detail) and actionable recommendations
- **Identity Confidence Score** — digital footprint strength, broken down by signal category with per-category point bars
- **Investigation Timeline** — chronological, icon-tagged, severity-colored event feed across every data source

---

### 🧠 Investigation Intelligence Suite

Everything below is derived purely from data the scan already collected — no extra API calls, no fabricated results, and anything unverifiable is explicitly labeled as such.

- **AI Investigation Summary** — plain-English narrative generated from the current scan, with a LOW/MEDIUM/HIGH confidence rating and a note explaining the basis for it.
- **Related Entities** — aggregates every email, domain, and username surfaced elsewhere in the scan (breaches, employee lookup, phone correlation, CT logs, OTX passive DNS) plus links to any previous cases on the same target.
- **Investigation Graph** (`/graph`) — D3 force-directed graph of target, IP, geo, subdomains, breaches, usernames, DNS, tech/cloud, SSL/CA, threats, and ports.
- **Entity Relationship Graph** (`/entity-graph`) — an expanded, standalone D3 force-directed graph that also folds in phone metadata, related entities, and IOC tags into one unified picture, distinct from the core `/graph` view above. Reads from the scan cache and falls back to an empty graph if no scan exists for the target.
- **Cross-Case Correlation** (`/cases/<id>/correlation`) — compares the current target/case against every other case in the system, surfacing shared indicators (phone/email/domain/username/IP/breach) ranked by a weighted overlap score. Requires both the Case Management and Cross-Case Correlation modules to be installed.
- **Social & Public Mention Search Suggestions** — clearly labeled search-suggestion links (Facebook, Instagram, LinkedIn, Telegram, Skype, GitHub, plus PDF/forum/resume/gov-doc dorks) with an on-screen disclaimer — no account existence is ever claimed without independent verification.
- **IOC Enrichment & Export** — structured Indicator-of-Compromise record (type, value, risk score, confidence, tags) exportable as **STIX 2.1** (`/export/ioc/stix`) or **MISP**-compatible JSON (`/export/ioc/misp`). Values are pulled directly from the Risk/Identity scores so exports stay consistent with what's on screen. Both export routes read the last-scanned target from the session and the scan cache — run a scan first.
- **Evidence Collection** — file uploads, one-click scan snapshots, and free-text investigator notes (`POST /cases/<id>/evidence/note`), all stored as timestamped evidence entries (`modules/investigations/evidence_store.py`).

---

### Image Intelligence Suite (`/image-osint`)

A consolidated route combining forensic metadata extraction with a full image analysis pipeline. Requires a logged-in user account (same public login as the Scanner). Every feature beyond core EXIF extraction is imported defensively — a missing dependency or model disables just that card without breaking the scan.

**Core — EXIF Metadata (ExifTool)**
- Drag-and-drop or click-to-browse upload (JPG, PNG, GIF, WEBP, TIFF, BMP, HEIC — max 15MB)
- Camera model, make, lens, date taken, ISO, aperture, shutter speed, focal length, resolution, flash, digital zoom, white balance, light source, orientation
- GPS detection with clear "not present" fallback when stripped
- Full raw metadata table with copy/download-as-JSON actions

**Analysis features (each isolated — a failure in one never blocks the others):**
1. **Image Hashing** — MD5, SHA256, pHash, dHash, aHash, wHash
2. **Duplicate Image Detection** — exact (SHA256) + perceptual (pHash) matching against previously indexed uploads
3. **QR / Barcode Detection** — decodes any embedded payload
4. **OCR Text Extraction** — per-line confidence scores
5. **Object Detection** — YOLOv11, per-object confidence
6. **Face Detection** — detection only, never identification; resolution-proportional minimum face size + secondary eye-cascade verification pass to suppress Haar-cascade false positives
7. **Face Attributes** — optional age/dominant-emotion estimate (DeepFace) + lightweight glasses/mask heuristic; framed as estimates, not verified facts
8. **Landmark Detection** — honestly reports "unconfigured" without `GOOGLE_VISION_API_KEY`
9. **Reverse Image Search** — labeled search-suggestion links (Google, Yandex, TinEye, Bing)
10. **GPS Extraction** — feeds a dedicated map card from EXIF data
11. **Metadata Privacy Risk Scoring** — flags how much personal/location data the file leaks
12. **AI Image Caption** — natural-language description (requires local caption model)
13. **AI-Generated Image Detection** — labeled `MODEL-BASED` or `HEURISTIC ESTIMATE`
14. **ELA / Forgery Detection** — Error Level Analysis for localized editing/splicing artifacts
15. **Image Quality Analysis** — sharpness/blur, brightness, contrast, noise estimate
16. **Color Palette Extraction** — dominant colors, average color, grayscale detection
17. **Logo & Brand Detection** — requires a configured detection backend
18. **Vehicle Make/Model Detection** — top prediction + ranked alternatives
19. **License Plate OCR** — requires a specialized OCR engine
20. **Similarity Search** — ranked near-duplicate lookup across indexed images (distinct from #2)

**Hardening:**
- Files deleted from disk immediately after processing (guaranteed `finally` cleanup)
- UUID-prefixed filenames + `secure_filename()` + path-containment guard
- Hard 15MB size cap and extension allow-list enforced server-side
- 15-second subprocess timeout on ExifTool
- Every scan audit-logged (`image_osint_scan`)

---

### Admin Panel
- **Dashboard** — scan stats, 7-day activity chart, top targets, live security-event counters
- **History** — full scan log with CSV export (bulk or single row)
- **Reports** — historical analytics (7d/30d/90d), exportable as JSON or PDF
- **Case Management** — create/track investigation cases with notes, priorities, tags, an Evidence Center (files + notes + snapshots), a dedicated Timeline view, and a per-case Intelligence panel
- **Scheduled Scans** — recurring target monitoring via APScheduler, with manual "run now" and enable/disable toggles
- **Alert Engine** — SMTP email alerts on breach detection or target change, plus webhook support and a test-alert button
- **User Management** — role-based access control for admin accounts (Admin / Analyst / Viewer)
- **Audit Logs** — every admin action *and* every public account action (register/login/logout, failed logins) logged with actor, action, detail, and IP
- **Target Change Monitor** — detects and flags changes between scans of a monitored target

> **Navigation note:** the public-facing pages (`/`, `/image-osint`) only show **Scanner** and **Image OSINT** in the nav bar, and both now require a logged-in public account (`/login`, `/register`). History, Cases, Reports, Scheduled Monitor, and Admin links live exclusively inside the authenticated admin panel (`/dashboard`, `/admin/*`) to avoid exposing internal tooling to unauthenticated visitors. Public accounts and admin accounts are entirely separate — a public login does not grant `/admin` access.

#### Investigation Intelligence (per-case, `/cases/<id>/intelligence`)
- **Confidence Score** — how much corroborated, verifiable data exists on the target (WHOIS, DNS, SSL, geo resolution, multi-source corroboration, note activity)
- **Risk Analysis** — LOW/MEDIUM/HIGH/CRITICAL, driven by dark-web flags, breach count, VT/OTX detections, AbuseIPDB score, risky ports, paste mentions, sensitive paths
- **Case Similarity** — cross-references every other case by tag overlap, shared root domain/IP/WHOIS org/subdomains/breach sources
- **Cross-Case Correlation** (`/cases/<id>/correlation`) — ranks other cases by concrete shared indicators (phone/email/domain/username/IP/breach) rather than similarity heuristics
- **Notes Intelligence** — structural summary of investigator notes (count, contributing analysts, latest entry)

Every step degrades gracefully — a sparse or malformed scan still renders a conservative score instead of a 500 error.

---

## Security

Four layers are active by default with zero configuration required, plus a public account gate in front of the scan features.

```
security/
├── rate_limiter.py      # Per-route request throttling
├── sql_protection.py    # SQL injection detection & blocking
├── captcha.py           # Math CAPTCHA + optional hCaptcha
├── jwt_auth.py           # JWT access & refresh tokens for API
├── redis_cache.py        # Optional: Redis-backed scan cache (falls back to in-memory)
├── logging_config.py     # Rotating file logs (app / error / security channels)
└── backup.py              # Automated DB + evidence backups with retention cleanup
```

The admin dashboard displays live counters for every security event — blocked injections, CAPTCHA pass/fail, rate-limit hits, JWT accept/reject, login attempts — via `/api/security-stats`.

### Layer 0 — Public Account Gate
`/` and `/image-osint` sit behind `@login_required`, checking `session["user_id"]`. Unauthenticated visitors are redirected to `/login` (with a `next` param back to the page they wanted). Accounts are created at `/register` — username + password (min. 8 characters, confirmed) behind the same CAPTCHA used elsewhere. This gate is independent of the admin session (`session["admin"]`); a public user can never reach `/dashboard` or `/admin/*`.

### Layer 1 — Rate Limiting
Flask-Limiter, per-session (falls back to IP).

| Endpoint group | Limit |
|---|---|
| Scan (`/`, `/image-osint`) | 10 / minute · 100 / day |
| Public account login/register (`/login`, `/register`) | 5 / minute · 20 / hour |
| Admin login (`/admin`) | 5 / minute · 20 / hour |
| API (`/api/*`) | 60 / minute |
| Export / PDF / IOC export | 10 / hour |
| Sensitive (user mgmt, alert test, evidence note/upload) | 3 / minute · 10 / hour |

Over-limit responses return HTTP **429** and are counted on the dashboard.

### Layer 2 — SQL Injection Protection
A `before_request` hook inspects every query-string/form parameter on every request; the scan target additionally passes through `sanitise_target()`, raising `SQLiDetected` on a match. Detects `UNION SELECT`, comment sequences, boolean/time-based blind patterns, `EXEC()`/`xp_cmdshell`, `CHAR()`/hex encoding tricks, `LOAD_FILE()`/`INTO OUTFILE`, and forbidden shell characters (`; ` $ | < > \`). Blocked requests return HTTP **400**. (The app uses SQLAlchemy ORM throughout — this is defense-in-depth.)

### Layer 3 — CAPTCHA
- **hCaptcha** when `HCAPTCHA_SITE_KEY` / `HCAPTCHA_SECRET_KEY` are set
- **Math CAPTCHA** fallback (zero-dependency, active by default) — a random addition problem with the expected answer HMAC-signed via `SECRET_KEY`, single-use
- Enforced on the scan form, the public register/login forms, and the admin login form

### Layer 4 — JWT Authentication
All `/api/*` endpoints returning scan/dashboard data require a Bearer token.

| Token | Lifetime |
|---|---|
| Access token | 15 minutes |
| Refresh token | 7 days |

Tokens carry a `jti`; logout blocklists it so it can't be reused before expiry. Roles (`admin`/`analyst`/`viewer`) are embedded and enforced per-endpoint.

| Route | Minimum role |
|---|---|
| `GET /api/result` | any authenticated |
| `GET /api/dashboard-stats` | analyst |
| `GET /api/target-history` | any authenticated |

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"yourpassword"}'

curl http://localhost:5000/api/result?target=example.com \
  -H "Authorization: Bearer <access_token>"
```

### Image Upload Hardening
Extension allow-list, 15MB server-enforced cap, `secure_filename()` sanitisation, UUID-prefixed storage names, path-containment check, ExifTool availability check, per-feature try/except isolation, guaranteed `finally` cleanup, 15-second subprocess timeout, full audit logging.

---

### Production Readiness (optional — Redis, logging, backups, PostgreSQL)

Three additional modules bring the platform from "self-hosted lab tool" to "deployable service." Each is **opt-in** — the app runs fine without them, on SQLite and in-memory caching, exactly as it does out of the box.

**Redis caching** — replace the in-memory scan cache with Redis so cached results survive restarts and are shared across multiple worker processes:

```env
REDIS_URL=redis://localhost:6379/0
CACHE_DEFAULT_TTL=3600
```

**Structured logging** — rotating log files instead of relying solely on stdout:

```
logs/app.log        general application log (10MB × 5 rotations)
logs/error.log       ERROR-level and above only (10MB × 10 rotations)
logs/security.log    dedicated security event channel
```

**Automated backups** — daily database + evidence-folder backups with retention cleanup:

```bash
python -m security.backup   # manual run
```

```env
BACKUP_DIR=backups
BACKUP_RETENTION_DAYS=14
```

Supports both SQLite (file copy) and PostgreSQL (`pg_dump`) automatically, based on `DATABASE_URL`.

**PostgreSQL** — swap the database backend for production without any model changes:

```env
DATABASE_URL=postgresql://osint_user:CHANGE_ME@localhost:5432/osint_db
```

Leave unset (or comment it out) to keep using SQLite — this is the default and requires no extra setup.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | random (change this!) | Flask session secret & CAPTCHA HMAC key |
| `JWT_SECRET_KEY` | random (change this!) | JWT signing secret |
| `FLASK_DEBUG` | `false` | Enable debug mode |
| `PORT` | `5000` | Port to run on |
| `DATABASE_URL` | `sqlite:///database.db` | SQLAlchemy database URI (SQLite or PostgreSQL) |
| `HCAPTCHA_SITE_KEY` | — | Enables hCaptcha widget (optional) |
| `HCAPTCHA_SECRET_KEY` | — | Enables hCaptcha verification (optional) |
| `REDIS_URL` | — | Enables Redis cache + shared rate-limit storage (optional) |
| `CACHE_DEFAULT_TTL` | `3600` | Redis cache entry TTL in seconds |
| `LOG_DIR` | `logs` | Directory for rotating log files |
| `LOG_LEVEL` | `INFO` | Root logging level |
| `BACKUP_DIR` | `backups` | Directory for automated backups |
| `BACKUP_RETENTION_DAYS` | `14` | Days before old backups are auto-deleted |
| `VT_API_KEY` | — | VirusTotal API key |
| `ABUSEIPDB_API_KEY` | — | AbuseIPDB API key |
| `URLSCAN_API_KEY` | — | URLScan.io API key |
| `OTX_API_KEY` | — | AlienVault OTX API key |
| `HIBP_API_KEY` | — | HaveIBeenPwned API key |
| `SPAM_API_KEY` | — | Optional licensed phone scam/fraud & spam-report provider (no free public API exists; feature honestly reports a heuristic estimate until configured) |
| `GOOGLE_VISION_API_KEY` | — | Optional provider key for Landmark Detection (Image Intelligence Suite); honestly reports "unconfigured" until set |

> Always set `SECRET_KEY` and `JWT_SECRET_KEY` to long random strings in production. Never leave them as the auto-generated defaults across restarts.
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

---

### Security Checklist for Production

- [ ] Set `FLASK_DEBUG=false`
- [ ] Set a strong `SECRET_KEY` (32+ random bytes)
- [ ] Set a strong `JWT_SECRET_KEY` (32+ random bytes)
- [ ] Set `REDIS_URL` for shared caching/rate-limit storage
- [ ] Add hCaptcha keys for stronger bot protection
- [ ] Run behind a reverse proxy (nginx / Caddy) with HTTPS
- [ ] Set `DATABASE_URL` to PostgreSQL instead of SQLite
- [ ] Confirm rotating logs are writing under `logs/`
- [ ] Confirm `python -m security.backup` runs cleanly, then let the scheduler take over
- [ ] Restrict `/admin/*` routes by IP in your reverse proxy
- [ ] Decide whether public self-registration (`/register`) should stay open, or be disabled/invite-only in front of your reverse proxy
- [ ] Confirm `exiftool` is installed on the host (`apt install exiftool`) before relying on Image Intelligence
- [ ] Confirm `phonenumbers` is installed (`pip install phonenumbers`) before relying on Phone Intelligence
- [ ] Confirm OCR/object-detection/face-detection model dependencies are installed if you want those Image Intelligence cards active
- [ ] Periodically check `uploads/` is empty — it should always self-clean, but monitor it as a safety net

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Database | SQLite (default) or PostgreSQL, via SQLAlchemy |
| Cache | In-memory (default) or Redis |
| Frontend | Vanilla JS, D3.js (graphs), CSS Variables |
| Auth | Public user session (scanner/image OSINT) + admin session (dashboard) + JWT (API) |
| Rate Limiting | Flask-Limiter |
| CAPTCHA | Math CAPTCHA (built-in) / hCaptcha (optional) |
| Scheduling | APScheduler |
| PDF Generation | ReportLab |
| Phone Intelligence | `phonenumbers` |
| Image Metadata | ExifTool (system binary, via subprocess) |
| Image Intelligence | Perceptual hashing, YOLOv11 (object detection), OCR engine, Haar-cascade face detection with eye-verification false-positive filtering, DeepFace (age/emotion), QR/barcode decoder |
| Threat Export | STIX 2.1 / MISP-compatible JSON (`modules/ioc_export.py`) |
| Logging | Python `logging` with rotating file handlers |

Every optional module is imported defensively at startup — if a module or its dependency is missing, the app disables just that feature and keeps running.

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/osint-platform.git
cd osint-platform
```

### 2. Create a virtual environment
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Install ExifTool (required for Image Intelligence Suite)
```bash
# Debian / Ubuntu
sudo apt install exiftool

# macOS (Homebrew)
brew install exiftool

# Windows — download from https://exiftool.org and add to PATH
```
If ExifTool isn't installed, `/image-osint` still loads but scans fail with a clear message. Individual analysis features degrade independently if their own dependency is missing.

### 5. Configure environment variables
Copy the block from [Environment Variables](#environment-variables) into a `.env` file at the project root.

### 6. Run the app
```bash
python app.py
```
Visit `http://127.0.0.1:5000`.

### 7. Create a scanner account
Go to `http://127.0.0.1:5000/register` and create a public account — this is required before you can use the Scanner or Image OSINT pages.

---

## First Admin Login

```bash
python - <<'EOF'
from app import app
from models import db, User

with app.app_context():
    db.create_all()
    u = User(username="admin", role="admin", is_active=True)
    u.set_password("yourpassword")
    db.session.add(u)
    db.session.commit()
    print("Admin user created.")
EOF
```
Then go to `http://127.0.0.1:5000/admin` and log in. This is entirely separate from the public `/register` / `/login` accounts used for scanning.

---

## User Roles

**Public accounts** (`/register`, `/login`) can use the Scanner and Image OSINT pages only — they have no access to History, Cases, Reports, Scheduled Monitor, or Admin.

**Admin-session roles** (created via `/admin/users`, logged in at `/admin`):

| Role | History | Cases | Intelligence | Correlation | Reports | Scheduled | Users | Audit |
|------|---------|-------|----------------|-------------|---------|-----------|-------|-------|
| **Viewer** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Analyst** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **Admin** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

> Everything in this table is gated behind `/admin` session auth; roles control *actions* (deleting history/cases/users, changing roles, and bulk deletes require `analyst` or `admin`).

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET/POST` | `/register` | None (CAPTCHA) | Create a public scanner account |
| `GET/POST` | `/login` | None (CAPTCHA) | Log in to a public scanner account |
| `GET` | `/logout-user` | Public session | Log out of the public scanner account |
| `POST` | `/api/auth/login` | None | Get JWT access + refresh token |
| `POST` | `/api/auth/refresh` | Refresh token | Get new access token |
| `POST` | `/api/auth/logout` | Bearer token | Revoke current token |
| `GET` | `/api/auth/me` | Bearer token | Current user info |
| `GET` | `/api/result?target=<t>` | Bearer token | Full cached scan result as JSON |
| `GET` | `/api/dashboard-stats` | Bearer (analyst+) | Overview statistics |
| `GET` | `/api/target-history?target=<t>` | Bearer token | Full scan history for a target |
| `GET` | `/api/security-stats` | Admin session | Live security event counters |
| `GET` | `/graph?target=<t>` | None | Investigation link graph data as JSON |
| `GET` | `/entity-graph?target=<t>` | None | Entity relationship graph data as JSON |
| `GET` | `/threat` | None | Dark web findings for latest scan |
| `GET` | `/export` | None | Export the latest scan as a PDF report |
| `GET` | `/export/ioc/stix` | Rate limited | Latest scan's IOC as a STIX 2.1 bundle |
| `GET` | `/export/ioc/misp` | Rate limited | Latest scan's IOC as a MISP-compatible event |
| `GET/POST` | `/` | Public session (rate limited) | Run a scan against a domain/IP/email/phone/username |
| `GET/POST` | `/image-osint` | Public session (rate limited) | Upload an image, run the full Image Intelligence Suite |
| `GET` | `/cases` | Admin session | List / filter / search cases |
| `POST` | `/cases/create` | Admin session | Create a case from the current scan |
| `GET` | `/cases/<id>` | Admin session | Case detail + notes |
| `POST` | `/cases/<id>/note` | Admin session | Add a case note |
| `POST` | `/cases/<id>/update` | Admin session | Update status/priority/description |
| `GET` | `/cases/<id>/export?format=json\|text` | Admin session | Export the case |
| `GET` | `/cases/<id>/report` | Admin session | Generate/download a per-case PDF report |
| `GET` | `/cases/<id>/evidence` | Admin session | Evidence Center |
| `POST` | `/cases/<id>/evidence/upload` | Admin session (sensitive limit) | Upload a file as evidence |
| `POST` | `/cases/<id>/evidence/note` | Admin session (sensitive limit) | Attach a free-text note as evidence |
| `POST` | `/cases/<id>/evidence/snapshot` | Admin session | Snapshot current scan data as evidence |
| `GET` | `/cases/<id>/evidence/<file>/download` | Admin session | Download an evidence file |
| `POST` | `/cases/<id>/evidence/<file>/delete` | Admin session (analyst+) | Delete an evidence file |
| `GET` | `/cases/<id>/timeline` | Admin session | Case-specific timeline |
| `GET` | `/cases/<id>/correlation` | Admin session | Cross-case correlation view |
| `GET` | `/cases/<id>/intelligence` | Admin session | Confidence score, risk analysis, similarity |
| `GET` | `/admin/scheduled` | Admin session | Manage scheduled scan targets |
| `POST` | `/admin/scheduled/add` | Admin session | Add a monitored target |
| `POST` | `/admin/scheduled/delete/<id>` | Admin session | Remove a monitored target |
| `POST` | `/admin/scheduled/toggle/<id>` | Admin session | Enable/disable monitoring |
| `POST` | `/admin/scheduled/run/<id>` | Admin session | Trigger an immediate scan |
| `GET` | `/admin/alerts` | Admin session | View/configure SMTP alert settings |
| `POST` | `/admin/alerts/save` | Admin session (admin role) | Save SMTP/webhook config |
| `POST` | `/admin/alerts/test` | Admin session (sensitive limit) | Send a test alert |
| `GET` | `/admin/reports` | Admin session | Historical analytics dashboard |
| `GET` | `/admin/reports/export` | Admin session | Export historical report as JSON |
| `GET` | `/admin/reports/export-pdf` | Admin session | Export historical report as PDF |
| `GET` | `/admin/export-csv` | Admin session (analyst+) | Export full scan history as CSV |
| `GET` | `/admin/export-csv/<id>` | Admin session | Export a single scan record as CSV |
| `GET` | `/admin/users` | Admin session (admin role) | Manage admin-side users |
| `POST` | `/admin/users/add` | Admin session (admin role) | Create an admin-side user |
| `POST` | `/admin/users/delete/<id>` | Admin session (admin role) | Delete a user |
| `POST` | `/admin/users/role/<id>` | Admin session (admin role) | Change a user's role |
| `GET` | `/admin/audit` | Admin session (admin role) | View audit log |
| `POST` | `/admin/delete/<id>` | Admin session (analyst+) | Delete a history entry |
| `POST` | `/admin/delete-all` | Admin session (admin role) | Delete all history |

---

## Project Structure

```
OSINT-Project/
├── app.py                      # Main Flask application & all routes
├── models.py                   # SQLAlchemy models (History, User, AuditLog, ScheduledTarget)
├── requirements.txt
│
├── security/                   # Security layer
│   ├── rate_limiter.py         # Per-route request throttling (Flask-Limiter)
│   ├── sql_protection.py       # SQLi pattern detection & before_request hook
│   ├── captcha.py              # Math CAPTCHA + hCaptcha integration
│   ├── jwt_auth.py             # JWT access/refresh tokens for API routes
│   ├── redis_cache.py          # Redis-backed scan cache with in-memory fallback
│   ├── logging_config.py       # Rotating file logging setup
│   └── backup.py                # Automated DB + evidence backups
│
├── modules/                    # OSINT intelligence modules (40+)
│   ├── intelligence/
│   │   ├── confidence_score.py  # Confidence + risk analysis (per-case)
│   │   └── case_similarity.py    # Case similarity + notes summary
│   ├── investigation/
│   │   └── investigation_dashboard.py
│   ├── investigations/
│   │   ├── evidence_store.py     # File + text evidence storage
│   │   └── timeline_builder.py
│   ├── image_intel/              # Image Intelligence Suite (20 features)
│   │   ├── image_hashing.py
│   │   ├── duplicate_detection.py
│   │   ├── qr_barcode.py
│   │   ├── ocr_extract.py
│   │   ├── object_detection.py
│   │   ├── face_detection.py
│   │   ├── face_attributes.py
│   │   ├── landmark_detection.py
│   │   ├── reverse_image_search.py
│   │   ├── gps_extraction.py
│   │   ├── metadata_risk.py
│   │   ├── caption.py
│   │   ├── ai_generated_detection.py
│   │   ├── forgery_detection.py
│   │   ├── image_quality.py
│   │   ├── color_palette.py
│   │   ├── logo_detection.py
│   │   ├── vehicle_detection.py
│   │   ├── license_plate_ocr.py
│   │   └── similarity_search.py
│   ├── abuse_lookup.py
│   ├── alert_engine.py
│   ├── archive_lookup.py
│   ├── case_management.py
│   ├── case_report_generator.py
│   ├── certificate_history.py
│   ├── cloud_detector.py
│   ├── dark_monitor.py
│   ├── cross_case_correlation.py   # Indicator overlap across cases
│   ├── directory_discovery.py
│   ├── dns_lookup.py
│   ├── dork_generator.py
│   ├── email.py
│   ├── employee_lookup.py
│   ├── entity_graph.py             # Expanded entity relationship graph builder
│   ├── geo.py
│   ├── headers_analysis.py
│   ├── identity_score.py
│   ├── investigation_summary.py    # AI-style plain-English investigation summary
│   ├── ioc_export.py               # STIX 2.1 / MISP IOC export
│   ├── leak_checker.py
│   ├── otx_lookup.py
│   ├── paste_monitor.py
│   ├── phone_lookup.py
│   ├── port_scan.py
│   ├── related_entities.py         # Emails/domains/usernames/case aggregation
│   ├── report.py
│   ├── report_dashboard.py
│   ├── reverse_ip.py
│   ├── risk_score.py
│   ├── robots_scan.py
│   ├── scheduled_scan.py
│   ├── screenshot.py
│   ├── social_search_links.py      # Labeled social/public-mention search suggestions
│   ├── ssl_info.py
│   ├── subdomain.py
│   ├── target_change_monitor.py
│   ├── tech_stake.py
│   ├── timeline.py
│   ├── urlscan_lookup.py
│   ├── username.py
│   ├── virustotal.py
│   └── whois_lookup.py
│
├── templates/                  # Jinja2 HTML templates
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── history.html
│   ├── image_upload.html
│   ├── image_result.html
│   ├── admin_dashboard.html
│   ├── admin_login.html
│   ├── admin_users.html
│   ├── admin_audit.html
│   ├── reports.html
│   ├── scheduled.html
│   ├── cases.html
│   ├── case_detail.html
│   ├── case_intelligence.html
│   ├── case_correlation.html
│   ├── evidence_center.html
│   ├── timeline.html
│   ├── alerts.html
│   └── error.html
│
├── static/
│   ├── style.css
│   └── graph.js
│
├── uploads/                    # Temporary image staging — self-cleans after each scan
│
└── docs/                       # Screenshots for README
```

---

## Performance

| Metric | Value |
|--------|-------|
| Average scan time | 4–8 seconds |
| Image metadata extraction | < 2 seconds (15s hard timeout) |
| Full Image Intelligence Suite (all features) | Varies by feature; each isolated with independent error handling |
| Concurrent scans | 20+ |
| Scan cache | 50 most recent targets (in-memory) |
| Rate limit | 10 scans/min · 100/day per session/IP |
| Database | SQLite by default; swap `DATABASE_URL` for Postgres in production |

---

## Known Limitations

- **Face Detection** uses OpenCV Haar cascades rather than a DNN-based detector. An eye-verification pass and resolution-proportional minimum face size cut false positives significantly, but Haar cascades can still misfire on unusual lighting, extreme angles, or heavily textured backgrounds.
- **Face Attributes** (age/emotion) rely on a pretrained DeepFace model and should be treated as estimates, not verified facts. Glasses/mask flags are a lightweight heuristic and can misfire on low-resolution crops.
- Several Image Intelligence cards (AI captioning, AI-generated detection, logo/vehicle/plate detection, landmark detection) require an external model or API key; without one they transparently report "unavailable" rather than a fabricated result.
- Reverse Image Search and Social/Public Mention links are **search suggestions only** — the platform never claims a confirmed match without independent verification.
- Public self-registration is open by default — anyone who can reach `/register` can create a scanner account. Disable or gate it in front of your reverse proxy if that's not desired.

---

## Ethical & Evidentiary Standards

This platform is built around one principle: **never present an unverified lead as a confirmed finding.**

- Username checks use real verification signals (HTTP 404s, page-specific error strings, title matching) — never a bare "got a 200 response" assumption.
- Social profile links and reverse-phone mention links for platforms that can't be reliably auto-verified are explicitly labeled as **search suggestions** with an on-screen disclaimer.
- The AI Investigation Summary only states what the underlying scan data actually supports, with a transparently-derived confidence level.
- Features requiring paid data (Phone Scam/Fraud Intelligence, Business Directory, Landmark Detection) clearly label results as `HEURISTIC ESTIMATE` or "unconfigured" when no provider is set.
- Face Detection is detection-only — no facial recognition or identity matching against any database.
- Reverse Image Search returns manual search-suggestion links, never a claimed match, until a public image URL provider is wired in.

---

## Legal Disclaimer

> This tool is intended for **educational and authorized security research only.**
> Do not scan targets you do not own or have explicit permission to test.
> Do not upload images you do not have the right to analyze.
> The author is not responsible for any misuse of this software.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you'd like to change.

---

*Built with Flask · D3.js · SQLAlchemy · Flask-Limiter · ExifTool · phonenumbers · PyJWT · APScheduler · ReportLab · DeepFace*