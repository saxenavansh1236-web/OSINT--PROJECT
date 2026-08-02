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
│(40+ modules)│ │ Dashboard    │ │Suite (24+    │ │Evidence   │ │Confidence/ │ │(in-memory /     │
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

## What's New

- **Three previously undocumented Image Intelligence features, now documented** — these already existed in the scan pipeline (`app.py`'s `image_osint()` route) but were missing from this README:
  - **Timeline Extraction** (`modules/image_intel/timeline_extractor.py`) — derives created/modified dates, file age, and timezone context from EXIF data, with an honest "cannot determine if shared/re-saved" label rather than asserting a chain of custody it can't verify.
  - **Camera Sensor Fingerprinting** (`modules/image_intel/camera_fingerprint.py`) — a noise-consistency heuristic that flags whether the sensor noise pattern across the frame looks uniform (consistent with a single, unedited capture) or inconsistent (possible splicing/editing), run directly against the file rather than metadata.
  - **AI Summary** (`modules/image_intel/ai_summary.py`) — a one-click consolidated summary that reads from the *entire* `image_intel` dict (metadata risk, hidden data, camera fingerprint, objects, OCR, etc.) and must run last in the pipeline since every other card feeds it. This is distinct from the per-image **AI Image Caption** feature, which only describes visual contents.
  - Total Image Intelligence feature count is corrected from "21+" to **24** to match what's actually wired up in `app.py`.
- **`hidden_data_extractor` is now a required, non-defensive import** — unlike every other Image Intelligence module (which is imported inside a `try/except ImportError` so the app degrades gracefully), `modules.image_intel.hidden_data_extractor` is imported directly at the top of `app.py`. If this module or its dependencies are missing, the app will fail to start rather than disabling just that card. Documented under Known Limitations/Installation below — make sure this module's dependencies are present before deploying.
- **Hidden Embedded Data Detection (Image Intelligence feature)** — some phone vendors (confirmed on OPPO/OnePlus devices) embed extra binary segments inside a JPEG's maker-note metadata that never show up when the photo is viewed normally — most notably `src.image`, a full secondary image that can be nearly half the file size and may show different content than the visible photo (e.g. a wider crop or an earlier/unprocessed frame), plus `rear.depth` (the portrait-mode depth map) and smaller watermark/mesh config blobs.
  - **`modules/image_intel/hidden_data_extractor.py`** — parses the `JSONInfo` field ExifTool already extracts, identifies known segment types by name, and honestly labels anything not in its known list as `Unrecognized embedded segment` rather than guessing what it is. Segments under 1KB (near-certainly small config blobs, not visual content) are collapsed into a single summary line instead of cluttering the results with 8+ near-empty entries.
  - **`modules/image_intel/metadata_risk.py`** — accepts the hidden-data finding as a second input and folds it into the overall 0–100 Metadata Risk score (capped contribution based on highest severity found, so multiple co-occurring segments from the same vendor format don't double-count), with a recommendation to re-export the photo through a basic editor to strip it before sharing.
  - Surfaced as its own **"Hidden Embedded Data"** card in the Image Intelligence results grid, showing each segment's label, size, byte offset, and a plain-English explanation of what it does and doesn't reveal.
- **Breach matching & risk scoring accuracy pass (v3)** — an audit of real scan output found that non-email targets (domains especially) were being run through the email breach-check pipeline regardless of type, because `app.py` calls a single `breach_check()` function for every scanned target. This produced badly misleading results — e.g. `google.com` scored **100/100 CRITICAL** off ~45 generic, unverified LeakCheck.io matches that merely mentioned the domain string, not confirmed breaches of any real mailbox.
  - **`leak_checker.py`** — `check_email()`/`check_username()`/`check_domain()`/`check_phone()` now verify the target actually matches their claimed type and self-correct to the right checker instead of blindly proceeding. Domain-wide LeakCheck.io matches (inherently broad/unverified for that API) are now labeled `medium` severity instead of `high`, explicitly described as unverified, and capped to the top 15 results. The username checker also now skips bare-domain-looking strings (e.g. won't probe `google.com` against Snapchat/Twitter/etc. as if it were a username).
  - **`risk_score.py`** — breach scoring is now confidence-weighted (a `verified: True` HaveIBeenPwned hit on a real email counts more than an unverified, non-email broad match) and the "breaches" category has a hard point cap, so one noisy source can no longer single-handedly push an otherwise-clean domain to a false CRITICAL score.
- **Export/report data-integrity pass (v2)** — an internal audit found that every export path (scan PDF, case PDF, IOC/STIX/MISP, historical JSON report) was silently dropping or misreporting data relative to what the live UI shows. All four are now fixed and consistent with on-screen results:
  - **Scan PDF (`/export`)** — previously only included 8 of the ~20+ fields in a scan result (target, ip, whois, subs, breach, username, ports, geo). Risk Score, Identity Score, AI Investigation Summary, Phone/Email Intelligence, DNS/SSL/Tech Stack, the Threat Intelligence Grid (VirusTotal/AbuseIPDB/OTX/URLScan), Dark Web/Paste Monitor findings, and Related Entities are now all included.
  - **IOC export (`/export/ioc/stix`, `/export/ioc/misp`)** — was reading the risk score from a key (`total_score`) the risk module doesn't actually produce, so every exported IOC showed `risk_score: 0` regardless of the real finding. Risk-level casing (`"HIGH"` vs. the lookup table's `"High"`) also silently mismatched, causing HIGH/CRITICAL findings to export to MISP tagged as the *lowest* threat level. Both are now normalized and verified against realistic data before export.
  - **Case PDF (`/cases/<id>/report`)** — didn't include the Investigation Intelligence panel (Confidence Score, Risk Analysis, Case Similarity) despite it being a headline per-case feature, and never included the investigator's actual written notes (only the evidence file list). Both are now in the report.
  - **Historical report (`/admin/reports`, `/admin/reports/export`, `/admin/reports/export-pdf`)** — `breach_count` was hardcoded to `0` in every report with no indication that it wasn't actually tracked, which reads as "no breaches" rather than "not measured." The report now exposes `breach_tracking_available` so this is stated honestly instead of silently defaulting to a false zero. A single malformed case/alert/scheduled-target row previously zeroed out that entire analytics section instead of being skipped — per-row fault isolation now prevents that. The hourly-distribution chart previously ignored the selected reporting period and always used a fixed 30-day window; it now matches whatever period (7d/30d/90d) is selected.
- **Image OSINT scans now visible on the Admin Dashboard** — image scans are audit-logged (`action="image_osint_scan"` in `AuditLog`) rather than written to the `History` table, since a file upload is a different kind of event than a target lookup. Previously the dashboard's `dashboard()` route computed `total_image_scans` but never rendered it in `admin_dashboard.html`, so image OSINT activity was invisible there even though it always showed correctly on `/history`. The dashboard now includes a dedicated **Image Scans** stat card and a **Recent Image OSINT Scans** table, both sourced from the same `AuditLog` query `/history` already used — no schema changes required.
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
- **Number Validity Detail** — separate `is_possible` (format-level) and `is_valid` (fully valid) checks with the raw `phonenumbers` validity type, so a number can be flagged as possible-but-not-valid rather than a single pass/fail
- **Number Pattern Analysis** — flags sequential digits, repeated-digit patterns, and known telemarketing ranges as anomaly signals distinct from carrier/line-type checks
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
- **Breach Check** — known data-breach exposure. Automatically detects and self-corrects if a target doesn't match its assumed type (e.g. a domain passed to the email checker is routed to the domain-appropriate check instead), so a bare domain can't be misrun through the email breach pipeline.
- **Leak Checker** — multi-source leak search across email, domain, phone, and username. Domain-wide matches are explicitly labeled as unverified/broad rather than presented with the same confidence as a verified email breach.
- **Risk Score** — 0–100 composite score with top risk factors (severity, points, category, detail) and actionable recommendations. Breach-derived points are confidence-weighted (verified email breaches count more than unverified/broad matches) and capped per category, so noisy or low-confidence signals can't single-handedly push the score to Critical.
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
- **IOC Enrichment & Export** — structured Indicator-of-Compromise record (type, value, risk score, confidence, tags) exportable as **STIX 2.1** (`/export/ioc/stix`) or **MISP**-compatible JSON (`/export/ioc/misp`). Values are pulled directly from the Risk/Identity scores so exports stay consistent with what's on screen — risk score and risk level are normalized before export so a HIGH/CRITICAL finding can never silently downgrade to a lower threat tier in the exported file. Both export routes read the last-scanned target from the session and the scan cache — run a scan first.
- **Evidence Collection** — file uploads, one-click scan snapshots, and free-text investigator notes (`POST /cases/<id>/evidence/note`), all stored as timestamped evidence entries (`modules/investigations/evidence_store.py`).

---

### Image Intelligence Suite (`/image-osint`)

A consolidated route combining forensic metadata extraction with a full image analysis pipeline. Requires a logged-in user account (same public login as the Scanner). Every feature beyond core EXIF extraction and Hidden Embedded Data Detection is imported defensively — a missing dependency or model disables just that card without breaking the scan. (Hidden Embedded Data Detection is imported as a hard, non-optional dependency — see Known Limitations.)

**Core — EXIF Metadata (ExifTool)**
- Drag-and-drop or click-to-browse upload (JPG, PNG, GIF, WEBP, TIFF, BMP, HEIC — max 15MB)
- Camera model, make, lens, date taken, ISO, aperture, shutter speed, focal length, resolution, flash, digital zoom, white balance, light source, orientation
- GPS detection with clear "not present" fallback when stripped
- Full raw metadata table with copy/download-as-JSON actions

**Analysis features (each isolated — a failure in one never blocks the others), in scan-pipeline order:**
1. **Image Hashing** — MD5, SHA256, pHash, dHash, aHash, wHash
2. **Duplicate Image Detection** — exact (SHA256) + perceptual (pHash) matching against previously indexed uploads
3. **QR / Barcode Detection** — decodes any embedded payload
4. **OCR Text Extraction** — per-line confidence scores
5. **Object Detection** — YOLOv11, per-object confidence
6. **Face Detection** — detection only, never identification; resolution-proportional minimum face size + secondary eye-cascade verification pass to suppress Haar-cascade false positives
7. **Landmark Detection** — honestly reports "unconfigured" without `GOOGLE_VISION_API_KEY`
8. **Reverse Image Search** — labeled search-suggestion links (Google, Yandex, TinEye, Bing)
9. **GPS Extraction** — feeds a dedicated map card from EXIF data
10. **Hidden Embedded Data Detection** — parses vendor-proprietary binary segments hidden inside maker-note metadata (confirmed on OPPO/OnePlus, referenced by name/offset/length in the `JSONInfo` field) that never appear when the photo is viewed normally. Flags known segment types (e.g. `src.image` — a full embedded secondary image that may show different content than the visible photo; `rear.depth` — the portrait-mode depth map) by name, size, and byte offset, with a plain-English explanation of what each does and doesn't reveal. Unrecognized segment names are honestly labeled as such rather than guessed at, and segments under 1KB are collapsed into a single summary line to avoid cluttering the card with near-empty entries.
11. **Metadata Privacy Risk Scoring** — flags how much personal/location data the file leaks, including a folded-in contribution from Hidden Embedded Data Detection when applicable
12. **AI Image Caption** — natural-language description (requires local caption model)
13. **AI-Generated Image Detection** — labeled `MODEL-BASED` or `HEURISTIC ESTIMATE`
14. **ELA / Forgery Detection** — Error Level Analysis for localized editing/splicing artifacts
15. **Timeline Extraction** *(new)* — created/modified dates, file age, and timezone context derived from EXIF, honestly labeled where the platform cannot verify sharing/re-save history
16. **Camera Sensor Fingerprinting** *(new)* — a noise-consistency heuristic run against the file itself (not metadata) to flag inconsistent sensor noise patterns that may indicate splicing or editing
17. **Face Attributes** — optional age/dominant-emotion estimate (DeepFace) + lightweight glasses/mask heuristic; framed as estimates, not verified facts
18. **Image Quality Analysis** — sharpness/blur, brightness, contrast, noise estimate
19. **Color Palette Extraction** — dominant colors, average color, grayscale detection
20. **Logo & Brand Detection** — requires a configured detection backend
21. **Vehicle Make/Model Detection** — top prediction + ranked alternatives
22. **License Plate OCR** — requires a specialized OCR engine
23. **Similarity Search** — ranked near-duplicate lookup across indexed images (distinct from #2)
24. **AI Summary** *(new)* — a one-click consolidated summary drawing on every card above (Investigation Summary, Risk, Camera Fingerprint, Hidden Metadata, Objects, OCR, and a recommendation); runs last in the pipeline since it depends on the rest

**Hardening:**
- Files deleted from disk immediately after processing (guaranteed `finally` cleanup)
- UUID-prefixed filenames + `secure_filename()` + path-containment guard
- Hard 15MB size cap and extension allow-list enforced server-side
- 15-second subprocess timeout on ExifTool
- Every scan audit-logged (`image_osint_scan`)

---

### Admin Panel
- **Dashboard** — scan stats, 7-day activity chart, top targets, live security-event counters, a dedicated **Image Scans** stat card, and a **Recent Image OSINT Scans** table (sourced from `AuditLog`, separate from the `History`-backed scan stats and chart)
- **History** — full scan log with CSV export (bulk or single row), plus a separate Image OSINT Scans section (also sourced from `AuditLog`)
- **Reports** — historical analytics (7d/30d/90d), exportable as JSON or PDF. A single malformed case/alert/scheduled-target record is skipped rather than blanking the entire section, and the hourly-activity chart always reflects the selected period rather than a fixed 30-day window.
- **Case Management** — create/track investigation cases with notes, priorities, tags, an Evidence Center (files + notes + snapshots), a dedicated Timeline view, and a per-case Intelligence panel
- **Scheduled Scans** — recurring target monitoring via APScheduler, with manual "run now" and enable/disable toggles
- **Alert Engine** — SMTP email alerts on breach detection or target change, plus webhook support and a test-alert button
- **User Management** — role-based access control for admin accounts (Admin / Analyst / Viewer)
- **Audit Logs** — every admin action *and* every public account action (register/login/logout, failed logins, image OSINT scans) logged with actor, action, detail, and IP
- **Target Change Monitor** — detects and flags changes between scans of a monitored target

> **Navigation note:** the public-facing pages (`/`, `/image-osint`) only show **Scanner** and **Image OSINT** in the nav bar, and both now require a logged-in public account (`/login`, `/register`). History, Cases, Reports, Scheduled Monitor, and Admin links live exclusively inside the authenticated admin panel (`/dashboard`, `/admin/*`) to avoid exposing internal tooling to unauthenticated visitors. Public accounts and admin accounts are entirely separate — a public login does not grant `/admin` access.

> **Data model note:** target scans (domain/IP/email/phone/username, run from `/`) are written to the `History` table and drive the dashboard's Total Scans / 7-Day Chart / Top Targets stats. Image OSINT scans (run from `/image-osint`) are a structurally different event — a file upload rather than a target lookup — and are written to `AuditLog` with `action="image_osint_scan"` instead. Both `/history` and `/dashboard` read from both tables to present a complete picture, but the two scan types are never merged into a single `History` row.

> **Breach tracking note:** the `History` table does not currently store a per-scan breach count, so historical/aggregate breach totals across time periods are not available — only the most recent cached scan's breach list is. The Reports module surfaces this honestly via a `breach_tracking_available` flag rather than defaulting to a misleading `0`. To enable real historical breach totals, add a `breach_count` column to `History` and populate it alongside `flagged` when a scan completes.

#### Investigation Intelligence (per-case, `/cases/<id>/intelligence`)
- **Confidence Score** — how much corroborated, verifiable data exists on the target (WHOIS, DNS, SSL, geo resolution, multi-source corroboration, note activity)
- **Risk Analysis** — LOW/MEDIUM/HIGH/CRITICAL, driven by dark-web flags, breach count, VT/OTX detections, AbuseIPDB score, risky ports, paste mentions, sensitive paths
- **Case Similarity** — cross-references every other case by tag overlap, shared root domain/IP/WHOIS org/subdomains/breach sources
- **Cross-Case Correlation** (`/cases/<id>/correlation`) — ranks other cases by concrete shared indicators (phone/email/domain/username/IP/breach) rather than similarity heuristics
- **Notes Intelligence** — structural summary of investigator notes (count, contributing analysts, latest entry)
- Also included in the per-case PDF export (`/cases/<id>/report`) — Confidence Score, Risk Analysis, Case Similarity, and the full investigator note history all render in the exported report, not just the web view.

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
A `before_request` hook inspects every query-string/form parameter on every request; the scan target additionally passes through `sanitise_target()`, raising `SQLiDetected` on a match. Detects `UNION SELECT`, comment sequences, boolean/time-based blind patterns, `EXEC()`/`xp_cmdshell`, `CHAR()`/hex encoding tricks, `LOAD_FILE()`/`INTO OUTFILE`, and forbidden shell characters (`; ` $ | < > \`). Blocked requests return HTTP **400**. (The app uses SQLAlchemy ORM throughout — this is defense-in-depth, not the sole protection against injection.)

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

> Always set `SECRET_KEY` and `JWT_SECRET_KEY` to long random strings in production. Never leave them as the auto-generated defaults across restarts — a default that's re-randomized on every process start will silently invalidate all active sessions and CAPTCHA tokens on every restart/deploy.
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

---

### Security Checklist for Production

- [ ] Set `FLASK_DEBUG=false`
- [ ] Set a strong `SECRET_KEY` (32+ random bytes) — do not rely on the auto-generated default
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
- [ ] Confirm `modules/image_intel/hidden_data_extractor.py` and its dependencies are present — this import is **not** wrapped defensively, so a missing dependency here will prevent the app from starting, unlike every other optional Image Intelligence module
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
| Image Intelligence | Perceptual hashing, YOLOv11 (object detection), OCR engine, Haar-cascade face detection with eye-verification false-positive filtering, DeepFace (age/emotion), QR/barcode decoder, vendor maker-note segment parsing (hidden embedded data), noise-consistency camera sensor fingerprinting, EXIF-derived timeline extraction, consolidated cross-feature AI summary |
| Threat Export | STIX 2.1 / MISP-compatible JSON (`modules/ioc_export.py`) |
| Logging | Python `logging` with rotating file handlers |

Every optional module is imported defensively at startup — if a module or its dependency is missing, the app disables just that feature and keeps running. (Exception: `hidden_data_extractor`, imported as a hard dependency — see Known Limitations.)

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
If ExifTool isn't installed, `/image-osint` still loads but scans fail with a clear message. Individual analysis features degrade independently if their own dependency is missing — with the exception of Hidden Embedded Data Detection (`hidden_data_extractor.py`), which is imported at the top of `app.py` outside the usual `try/except ImportError` pattern. Make sure this module and its dependencies are present, or the whole app will fail to start.

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
| `GET` | `/export` | None | Export the latest scan as a full PDF report (all sections — risk/identity scores, threat intel, phone/email intel, etc.) |
| `GET` | `/export/ioc/stix` | Rate limited | Latest scan's IOC as a STIX 2.1 bundle, with normalized risk score/level |
| `GET` | `/export/ioc/misp` | Rate limited | Latest scan's IOC as a MISP-compatible event, with normalized threat level |
| `GET/POST` | `/` | Public session (rate limited) | Run a scan against a domain/IP/email/phone/username |
| `GET/POST` | `/image-osint` | Public session (rate limited) | Upload an image, run the full Image Intelligence Suite |
| `GET` | `/cases` | Admin session | List / filter / search cases |
| `POST` | `/cases/create` | Admin session | Create a case from the current scan |
| `GET` | `/cases/<id>` | Admin session | Case detail + notes |
| `POST` | `/cases/<id>/note` | Admin session | Add a case note |
| `POST` | `/cases/<id>/update` | Admin session | Update status/priority/description |
| `GET` | `/cases/<id>/export?format=json\|text` | Admin session | Export the case |
| `GET` | `/cases/<id>/report` | Admin session | Generate/download a per-case PDF report, including Investigation Intelligence and full investigator notes |
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
| `GET` | `/admin/reports/export` | Admin session | Export historical report as JSON (includes `breach_tracking_available` and `data_limitations` fields) |
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
│   ├── image_intel/              # Image Intelligence Suite (24 features)
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
│   │   ├── metadata_risk.py          # now also scores Hidden Embedded Data findings
│   │   ├── hidden_data_extractor.py  # vendor maker-note segment detection (e.g. OPPO/OnePlus src.image, rear.depth) — hard dependency, imported non-defensively in app.py
│   │   ├── caption.py
│   │   ├── ai_generated_detection.py
│   │   ├── forgery_detection.py
│   │   ├── image_quality.py
│   │   ├── color_palette.py
│   │   ├── logo_detection.py
│   │   ├── vehicle_detection.py
│   │   ├── license_plate_ocr.py
│   │   ├── similarity_search.py
│   │   ├── timeline_extractor.py     # NEW — EXIF-derived created/modified/age/timezone
│   │   ├── camera_fingerprint.py     # NEW — noise-consistency sensor fingerprinting
│   │   └── ai_summary.py             # NEW — consolidated cross-feature summary (runs last)
│   ├── abuse_lookup.py
│   ├── alert_engine.py
│   ├── archive_lookup.py
│   ├── case_management.py
│   ├── case_report_generator.py     # v2: now includes Investigation Intelligence + investigator notes
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
│   ├── ioc_export.py               # STIX 2.1 / MISP IOC export — v2: normalized risk score/level
│   ├── leak_checker.py               # v3: type self-correction, confidence-labeled domain matches
│   ├── otx_lookup.py
│   ├── paste_monitor.py
│   ├── phone_lookup.py
│   ├── port_scan.py
│   ├── related_entities.py         # Emails/domains/usernames/case aggregation
│   ├── report.py                    # Scan PDF export — v2: full field coverage
│   ├── report_dashboard.py          # Historical reports — v2: honest breach tracking, per-row fault isolation
│   ├── reverse_ip.py
│   ├── risk_score.py                  # v3: confidence-weighted breach scoring, category cap
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
| Full Image Intelligence Suite (all 24 features) | Varies by feature; each isolated with independent error handling |
| Concurrent scans | 20+ |
| Scan cache | 50 most recent targets (in-memory) |
| Rate limit | 10 scans/min · 100/day per session/IP |
| Database | SQLite by default; swap `DATABASE_URL` for Postgres in production |

---

## Known Limitations

- **`hidden_data_extractor` is a hard dependency**, unlike every other Image Intelligence module. It's imported directly at the top of `app.py` (`from modules.image_intel import hidden_data_extractor`) rather than inside a `try/except ImportError` block, so if this module or its dependencies are missing, the entire app fails to start rather than just disabling that one card. Confirm it's present before deploying.
- **Face Detection** uses OpenCV Haar cascades rather than a DNN-based detector. An eye-verification pass and resolution-proportional minimum face size cut false positives significantly, but Haar cascades can still misfire on unusual lighting, extreme angles, or heavily textured backgrounds.
- **Face Attributes** (age/emotion) rely on a pretrained DeepFace model and should be treated as estimates, not verified facts. Glasses/mask flags are a lightweight heuristic and can misfire on low-resolution crops.
- **Camera Sensor Fingerprinting** is a noise-consistency heuristic, not a forensic-grade PRNU (Photo Response Non-Uniformity) match against a known camera. It flags *inconsistency* within a single frame as a possible editing signal — it does not identify which camera captured the image or confirm authenticity.
- **Timeline Extraction** can only report what EXIF data provides; it cannot verify whether a photo has been re-saved, re-uploaded, or passed through a platform that strips/rewrites timestamps, and labels this limitation honestly rather than asserting an unbroken chain of custody.
- **AI Summary** is only as complete as the cards that ran before it — if an upstream feature (e.g. object detection) is disabled due to a missing dependency, the summary reflects that gap rather than fabricating a finding.
- **Hidden Embedded Data Detection** only recognizes segment *names* it has been told about (currently tuned against OPPO/OnePlus's `JSONInfo` format). Other vendors may use a different metadata structure entirely, in which case this feature reports "not applicable to this file" rather than a false negative. Recognized-but-unlisted segment names are shown honestly as "unrecognized" rather than guessed at.
- Several Image Intelligence cards (AI captioning, AI-generated detection, logo/vehicle/plate detection, landmark detection) require an external model or API key; without one they transparently report "unavailable" rather than a fabricated result.
- Reverse Image Search and Social/Public Mention links are **search suggestions only** — the platform never claims a confirmed match without independent verification.
- Public self-registration is open by default — anyone who can reach `/register` can create a scanner account. Disable or gate it in front of your reverse proxy if that's not desired. Because scans consume third-party API quota (VT, AbuseIPDB, OTX, etc.), open registration is also a cost/abuse surface, not just a privacy one — consider email verification or an invite code if this matters for your deployment.
- Image OSINT scans and target scans are tracked in two separate tables (`AuditLog` vs. `History`) by design, since they represent different kinds of events. Both `/history` and `/dashboard` merge them for display, but any custom reporting or export you build on top of the database directly needs to query both tables to get a full picture of scan activity.
- **Historical breach totals** are not tracked — the `History` table records whether a scan was flagged, not how many breaches were found, so `/admin/reports` cannot show a true breach count over time. This is surfaced explicitly via `breach_tracking_available: false` rather than a misleading `0`. See the Admin Panel section above for how to enable it.
- `SECRET_KEY` / `JWT_SECRET_KEY` default to a value randomly generated at process start if not set in the environment. This is fine for local testing but means every restart invalidates all sessions/tokens in that state — always set both explicitly before deploying anywhere persistent.
- **Domain-wide breach matches remain inherently lower-confidence.** LeakCheck.io's public API isn't designed for domain-scoped lookups, so even after the v3 type-correction and confidence-weighting fixes, a "leak" surfaced for a bare domain means the string appeared somewhere in their index — not that a specific mailbox @domain was confirmed compromised. These are labeled `medium` severity and described as unverified, but they should still be treated as leads for manual verification, not confirmed findings, consistent with this platform's evidentiary standard.

---

## Ethical & Evidentiary Standards

This platform is built around one principle: **never present an unverified lead as a confirmed finding.**

- Username checks use real verification signals (HTTP 404s, page-specific error strings, title matching) — never a bare "got a 200 response" assumption.
- Social profile links and reverse-phone mention links for platforms that can't be reliably auto-verified are explicitly labeled as **search suggestions** with an on-screen disclaimer.
- The AI Investigation Summary (target scans) and AI Summary (image scans) only state what the underlying data actually supports, with a transparently-derived confidence level.
- Features requiring paid data (Phone Scam/Fraud Intelligence, Business Directory, Landmark Detection) clearly label results as `HEURISTIC ESTIMATE` or "unconfigured" when no provider is set.
- Face Detection is detection-only — no facial recognition or identity matching against any database.
- Reverse Image Search returns manual search-suggestion links, never a claimed match, until a public image URL provider is wired in.
- **Camera Sensor Fingerprinting** reports a noise-consistency flag, never a confirmed forgery verdict or camera identification.
- **Timeline Extraction** reports what EXIF states, never an asserted, verified chain of custody.
- **Hidden Embedded Data Detection** identifies known vendor segment types by name and honestly labels anything outside its known list as "unrecognized" rather than asserting what it contains — the tool reports that a hidden secondary image *may* show different content than the visible photo, not that it definitely does, since that can only be confirmed by extracting and viewing the segment directly.
- Exported reports (PDF, STIX, MISP, JSON) are held to the same standard as the UI: risk/confidence values are normalized before export so an exported finding can't silently understate what the live scan actually showed, and metrics that aren't really tracked (e.g. historical breach totals) are labeled as such rather than defaulted to a number that looks like a real result.
- Breach/leak matches are weighted by how confident the underlying match actually is — a confirmed, verified breach on a real email is never scored or displayed identically to an unverified, broad domain-wide match. This is the same principle applied consistently: a low-confidence lead should never look like a confirmed finding, whether that's a social-profile link, an AI-generated summary, or a risk score.

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
