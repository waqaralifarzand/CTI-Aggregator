# CLAUDE.md — CTI Aggregator Project Identity

> Read this file first. Every session. No exceptions.

---

## Project Identity

**Project Name:** CTI Aggregator — Automated Cyber Threat Intelligence Aggregator & Normalization Framework
**Repo URL:** https://github.com/waqaralifarzand/CTI-Aggregator
**Deployment Target:** Local only (no cloud deployment — runs on localhost)
**Academic Context:** Final Year Project (FYP), Department of Forensic Sciences & Criminology (DFRSC), Lahore Garrison University

---

## What This Product IS

A web-based cyber threat intelligence platform that allows security analysts to look up Indicators of Compromise (IoCs) — IP addresses, domains, and file hashes — against multiple open-source threat feeds. The system aggregates, normalizes, and classifies threat data, presents results in a Sucuri SiteCheck-inspired dashboard, and uses a machine learning classifier to assign severity scores. It includes a bulk IoC scanner, live threat ticker, scan history, shareable result URLs, and exportable reports.

---

## What This Product IS NOT

- NOT a real-time network monitor or packet inspector
- NOT a vulnerability scanner (no port scanning, no CVE lookup)
- NOT a SIEM or log aggregation tool
- NOT a cloud-hosted SaaS product — runs entirely on localhost
- NOT connected to MISP, VirusTotal, Shodan, or any paid APIs
- NOT a WordPress/website scanner (the Sucuri design is inspiration only — the product does IoC lookup, not site scanning)
- NOT a multi-user platform — single analyst use, no auth/login system

---

## Tech Stack — LOCKED. No deviations during execution.

| Layer | Technology | Version |
|---|---|---|
| Frontend Framework | React | 18 |
| Frontend Build Tool | Vite | 5 |
| Frontend Styling | Tailwind CSS | 3 |
| Frontend Charts | Recharts | 2 |
| Frontend HTTP Client | Axios | 1.x |
| Backend Framework | FastAPI | 0.111+ |
| Backend Language | Python | 3.11+ |
| Backend HTTP Client | httpx | 0.27+ |
| ORM | SQLAlchemy | 2.x |
| Database (dev) | SQLite | built-in |
| Database (prod-ready) | PostgreSQL | 16 (schema compatible) |
| ML Library | scikit-learn | 1.5+ |
| Data Processing | pandas | 2.x |
| Validation | Pydantic | 2.x |
| Background Tasks | FastAPI BackgroundTasks | built-in |
| CORS | fastapi.middleware.cors | built-in |

---

## Threat Feed Integrations — LOCKED

| Feed | Source | IoC Types |
|---|---|---|
| AlienVault OTX | https://otx.alienvault.com/api/v1 | IP, Domain, Hash |
| Abuse.ch URLhaus | https://urlhaus-api.abuse.ch/v1 | Domain, URL |
| Abuse.ch MalwareBazaar | https://mb-api.abuse.ch/api/v1 | File Hash (MD5, SHA256) |
| ip-api.com | http://ip-api.com/json (free tier) | IP Geolocation |
| WHOIS (python-whois) | Local library lookup | Domain registration data |
| VirusTotal | https://www.virustotal.com/api/v3 | IP, Domain, Hash | Key: from `VT_API_KEY` env var |

No paid APIs. No API keys required except OTX (free registration) and VirusTotal (free registration, 4 req/min limit).

---

## Design System

**Aesthetic Direction:** Industrial dark — Sucuri SiteCheck inspired. Utilitarian. Professional. Feels like a real security tool, not a student project.

**Color Palette (CSS variables — locked):**
```css
--bg-primary:     #0a0e1a;   /* deep navy — main background */
--bg-card:        #111827;   /* dark card background */
--bg-card-hover:  #1a2235;   /* card hover state */
--border:         #1f2d3d;   /* subtle border */
--accent:         #06b6d4;   /* cyan — interactive elements, links, buttons */
--accent-hover:   #0891b2;   /* cyan hover */
--text-primary:   #f1f5f9;   /* near-white — headings */
--text-secondary: #94a3b8;   /* muted slate — body, labels */
--text-muted:     #475569;   /* very muted — hints, placeholders */

/* Severity colors — non-negotiable */
--critical:       #ef4444;   /* red */
--high:           #f97316;   /* orange */
--medium:         #eab308;   /* yellow */
--low:            #22c55e;   /* green */
--clean:          #10b981;   /* emerald */
--info:           #3b82f6;   /* blue — informational */
```

**Typography:**
- Display / UI: `DM Sans` (Google Fonts) — headings, nav, labels
- Monospace: `JetBrains Mono` (Google Fonts) — IoC values, hashes, IPs, code
- Body size: 14px base, 16px for content areas

**Layout:**
- Fixed left sidebar navigation (240px wide)
- Main content area fills remaining width
- Cards with 1px border, subtle background — no heavy shadows
- Severity badges: pill shape, colored background at 15% opacity + colored text

---

## Pages & Routes

| Route | Page | Description |
|---|---|---|
| `/` | Home — IoC Scanner | Hero search bar + live result panels |
| `/results/:scanId` | Scan Results | Shareable permalink for a specific scan |
| `/dashboard` | Dashboard | Stats, charts, feed health, recent scans |
| `/reports` | Reports | Full scan history, filters, CSV export |
| `/feeds` | Feed Manager | OTX + Abuse.ch status, manual refresh |
| `/ml` | ML Insights | Model metrics, feature importance, retrain |
| `/bulk` | Bulk Scanner | CSV upload, batch IoC scanning |

---

## Hard Rules for Claude Code

1. **Never push to main.** Every phase goes to a new branch. PR always.
2. **Never deviate from the locked tech stack.** No new libraries without planning chat approval.
3. **Never guess on ambiguous specs.** Document the question in SCRATCHPAD.md and continue with other tasks.
4. **Never add authentication/login.** Out of scope.
5. **Never make live API calls during component rendering.** All calls go through the `/api` backend — never direct from frontend to OTX/Abuse.ch.
6. **Always update SCRATCHPAD.md** at the end of each phase before committing.
7. **Always use CSS variables** for colors — never hardcode hex values in components.
8. **SQLite in dev.** Use `DATABASE_URL` env var so PostgreSQL works as drop-in replacement.
9. **All API responses use standard envelope:** `{ success: bool, data: any, error: str | null }`
10. **IoC type must be auto-detected** server-side — never ask the user to specify type manually.

---

## Environment Variables

```env
# Backend (.env in /backend)
DATABASE_URL=sqlite:///./cti_aggregator.db
OTX_API_KEY=your_otx_key_here
CORS_ORIGINS=http://localhost:5173

# Frontend (.env in /frontend)
VITE_API_BASE_URL=http://localhost:8000
```

---

## Audience & Business Context

**Primary user:** A single security analyst or forensic student running the tool locally to investigate IoCs during threat research or academic analysis.

**Presentation context:** FYP demonstration to university supervisor and panel. The tool must look professional, run without internet-dependent auth, and demonstrate all 8 phases of the project proposal (collection, normalization, anomaly detection, correlation, ML classification, interface, reporting, evaluation).

**Academic proposal alignment:**
- Phases 1–2 of proposal → Backend feed integration (covered in project Phases 2)
- Phase 3 (rule-based detection) → Abuse.ch + OTX cross-referencing logic
- Phase 4 (correlation) → Multi-feed result aggregation + scan history comparison
- Phase 5 (ML classification) → Random Forest severity classifier (project Phase 6)
- Phase 6 (CLI) → REPLACED by web dashboard (approved by supervisor)
- Phase 7 (reporting) → CSV export + shareable URLs (project Phase 5)
- Phase 8 (testing) → project Phase 8

---

## Project Boundaries — Repeat for Emphasis

This is a local-only, single-user, IoC intelligence lookup tool. It does not scan networks, monitor live traffic, or replace enterprise SIEM tools. Its value is in aggregating public threat intelligence feeds, normalizing them into a clean interface, and applying ML classification — making threat research faster for a solo analyst.
