# SCRATCHPAD.md — CTI Aggregator Session Memory

> This file is updated by Claude Code at the END of every phase before committing.
> The planning chat reads this to understand current project state before generating the next prompt.
> Never delete old entries — append only.

---

## Entry Format (use this template for every phase)

```
## Phase N — [Phase Title]
**Date:** YYYY-MM-DD
**Branch:** phase-N-description
**Status:** ✅ Complete | 🔄 Partial | ❌ Blocked

### What Was Built
- [bullet list of what was actually created/modified]

### What Works
- [bullet list of verified working functionality]

### What's Pending / Skipped
- [anything not completed, with reason]

### Known Issues
- [bugs, quirks, or edge cases discovered]

### Mid-Execution Decisions
- [any deviation from ARCHITECTURE.md with reason]

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- [exact starting point for Phase N+1]
```

---

## Phase 1 — Repo Setup: Backend + Frontend Skeleton
**Date:** 2026-05-26
**Branch:** claude/trusting-dirac-V4y3q
**Status:** ✅ Complete

### What Was Built
- `.gitignore` — covers `__pycache__`, `.env`, `*.pkl`, `node_modules`, `*.db`, `.venv`, `dist`
- `README.md` — placeholder run instructions
- `backend/requirements.txt` — all dependencies at exact pinned versions
- `backend/.env.example` — committed placeholder template
- `backend/.env` — local secrets file (NOT committed)
- `backend/database.py` — SQLAlchemy engine, SessionLocal, Base, get_db, create_tables
- `backend/models/ioc.py` — IoC ORM model (table: iocs)
- `backend/models/scan_result.py` — ScanResult ORM model (table: scan_results)
- `backend/models/feed_result.py` — FeedResult ORM model (table: feed_results, cascade delete)
- `backend/models/feed_status.py` — FeedStatus ORM model (table: feed_status)
- `backend/models/bulk_job.py` — BulkJob ORM model (table: bulk_jobs)
- `backend/models/__init__.py` — imports all 5 models
- `backend/utils/response.py` — ok() and err() helpers
- `backend/routers/scan.py` — stub: POST /api/scan, GET /api/scan/{scan_id}, GET /api/scans/recent
- `backend/routers/bulk.py` — stub: POST /api/bulk/scan, GET /api/bulk/{job_id}
- `backend/routers/feeds.py` — stub: GET /api/feeds, POST /api/feeds/{feed_name}/refresh
- `backend/routers/reports.py` — stub: GET /api/reports, GET /api/reports/export
- `backend/routers/ml.py` — stub: GET /api/ml/metrics, POST /api/ml/train, GET /api/ml/features
- `backend/routers/dashboard.py` — stub: 5 dashboard endpoints
- `backend/main.py` — FastAPI app, CORS, startup table creation, all routers registered
- `backend/.venv/` — Python virtual environment with all deps installed
- `frontend/` — Vite + React scaffold
- `frontend/tailwind.config.js` — content paths configured
- `frontend/index.html` — Google Fonts (DM Sans + JetBrains Mono) added
- `frontend/src/index.css` — all CSS variables, base reset, shimmer animation, scrollbar
- `frontend/.env` — VITE_API_BASE_URL=http://localhost:8000
- `frontend/src/api/client.js` — Axios instance + all 15 stub API functions
- `frontend/src/components/layout/PageWrapper.jsx` — consistent padding wrapper
- `frontend/src/components/layout/Sidebar.jsx` — fixed 240px nav with 6 links, active state
- `frontend/src/pages/Home.jsx` — stub page
- `frontend/src/pages/Results.jsx` — stub page
- `frontend/src/pages/Dashboard.jsx` — stub page
- `frontend/src/pages/Reports.jsx` — stub page
- `frontend/src/pages/Feeds.jsx` — stub page
- `frontend/src/pages/MLInsights.jsx` — stub page
- `frontend/src/pages/Bulk.jsx` — stub page
- `frontend/src/App.jsx` — React Router v6 with all 7 routes
- `frontend/src/main.jsx` — ReactDOM.createRoot entry point

### What Works
- ✅ GET http://localhost:8000/api/health → {"success":true,"data":{"status":"ok","db":"connected"},"error":null}
- ✅ http://localhost:8000/docs → Swagger UI shows all 18 stub endpoints
- ✅ All 5 DB tables created: bulk_jobs, feed_results, feed_status, iocs, scan_results
- ✅ http://localhost:5173 responds HTTP 200
- ✅ Frontend builds clean (npm run build — 0 errors)
- ✅ Sidebar with 6 nav links, dark background, CSS variables applied
- ✅ All 7 routes defined (Home, Results, Dashboard, Reports, Feeds, MLInsights, Bulk)
- ✅ backend/.env NOT staged for commit

### What's Pending / Skipped
- None — all Phase 1 tasks complete

### Known Issues
- None

### Mid-Execution Decisions
- Branch deviation: environment requires `claude/trusting-dirac-V4y3q` instead of `phase-1-skeleton`. All work committed to this branch per system constraint.
- DB file created at project root (./cti_aggregator.db) when server runs from project root — correct behavior for sqlite:///./cti_aggregator.db relative path.
- Sidebar hover effect uses onMouseEnter/onMouseLeave inline handlers since NavLink inline style callback only fires on active state changes, not hover.

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- Phase 2: Feed Integration — implement ioc_detector.py, otx_service.py, abusech_service.py, geo_service.py, whois_service.py, severity.py, aggregator_service.py, and fully implement POST /api/scan with DB writes.

---

## Phase 2 — Feed Integration: IoC Detection + OTX + Abuse.ch + Scan Endpoint
**Date:** 2026-05-26
**Branch:** claude/trusting-dirac-V4y3q
**Status:** ✅ Complete

### What Was Built
- `CLAUDE.md` — VirusTotal added to Feed Integrations table
- `ARCHITECTURE.md` — vt_service.py in services listing, VT_API_KEY in env sections, virustotal as valid feed_name, VTPanel.jsx in component map
- `backend/.env` — VT_API_KEY=placeholder_key added
- `backend/.env.example` — VT_API_KEY=REPLACE_WITH_YOUR_VT_KEY added
- `backend/services/ioc_detector.py` — detect_type() using ipaddress lib + regex; handles IPv4/IPv6, MD5(32), SHA256(64), SHA1(40), domain; raises ValueError for unrecognized
- `backend/services/otx_service.py` — query_otx() async httpx; maps ioc_type to OTX endpoint; normalizes pulse_count, threat_tags, categories, country; graceful 404/error handling
- `backend/services/abusech_service.py` — query_urlhaus() (POST /host/ for ip/domain), query_malwarebazaar() (POST get_info for hashes); graceful N/A handling for wrong type
- `backend/services/vt_service.py` — query_virustotal() for /files/, /ip_addresses/, /domains/; returns detections + total_engines + flagged_engines; skips if key is placeholder
- `backend/services/geo_service.py` — query_geo() async httpx to ip-api.com; returns country/city/isp/asn or None
- `backend/services/whois_service.py` — query_whois() runs python-whois in thread executor (asyncio.wait_for 10s); returns registrar/dates/name_servers or None
- `backend/services/aggregator_service.py` — run_scan() orchestrates all feeds with asyncio.gather; detects type → queries applicable feeds concurrently → computes score/severity → returns full response dict with UUID scan_id
- `backend/utils/severity.py` — compute_score() (OTX: +20/+15/+25 pulse tiers, +15 high-risk tags; URLhaus +30; MB +35; combo +10; VT: +20/+30/+40 detection tiers); score_to_severity(); generate_recommendations() (2–3 bullets)
- `backend/schemas/scan.py` — ScanRequest (with validator), IocInfo, GeoData, WhoisData, BlacklistStatus, ScanResponse, RecentScanItem
- `backend/schemas/feed.py` — FeedStatusResponse, FeedRefreshResponse
- `backend/routers/scan.py` — full POST /api/scan (upsert IoC + new ScanResult + FeedResult rows), GET /api/scan/{scan_id} (JSON from raw_summary), GET /api/scans/recent
- `backend/routers/feeds.py` — GET /api/feeds (all feed_status rows), POST /api/feeds/{feed_name}/refresh (ping feed + update status)
- `backend/main.py` — _seed_feed_status() on startup: upserts otx/urlhaus/malwarebazaar/virustotal rows

### What Works
- ✅ POST /api/scan {"value": "8.8.8.8"} → HTTP 200, success:true, correct structure, DB written
- ✅ POST /api/scan {"value": "44d88612fea8a8f36de82e1278abb02f"} → HTTP 200, hash_md5 detected, urlhaus.applicable=false
- ✅ POST /api/scan {"value": "google.com"} → HTTP 200, domain detected, urlhaus.applicable=true
- ✅ Same IoC scanned twice → scan_count incremented (8.8.8.8 shows scan_count=2)
- ✅ GET /api/scan/{scan_id} → returns stored raw_summary JSON
- ✅ GET /api/scans/recent?limit=3 → returns 3 most recent with correct fields
- ✅ GET /api/feeds → returns 4 feeds with display names
- ✅ All 5 DB tables written: iocs (3 rows), scan_results (4 rows), feed_results (16 rows), feed_status (4 rows seeded)
- ✅ Invalid IoC → HTTP 422 with error message
- ✅ Empty value → HTTP 422 Pydantic validation error
- ✅ No 500 errors on any test

### What's Pending / Skipped
- Live feed data returns clean/null because sandbox network blocks external APIs (ip-api.com, OTX, Abuse.ch, VT hostnames not in allowlist). All error paths handled gracefully.
- POST /api/feeds/{feed_name}/refresh tested structurally but ping returns error (expected in sandbox)

### Known Issues
- External APIs blocked in sandbox environment — real threat data will appear when run locally with valid API keys and network access. Error handling confirmed graceful.
- WHOIS returns None in sandbox (network blocked) — correct behavior per spec

### Mid-Execution Decisions
- Branch: same `claude/trusting-dirac-V4y3q` per system constraint (not `phase-2-feed-integration`)
- VT scoring added: detections>0 +20, >10 +30, >30 +40 (as specified in prompt)
- `feeds` dict in response includes geo/whois keys even for non-applicable types (null values) — frontend can check null safely
- ScanResult.scanned_at stored as UTC datetime; .isoformat() used in GET responses
- ip-api.com geo request includes `?fields=` param to minimize response size

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- Phase 3: Home page + Results page UI — ScanBar, IocTypeBadge, all result panel components (OTXPanel, AbuseChPanel, VTPanel, GeoPanel, WhoisPanel, MLPredictionPanel, BlacklistPanel, RecommendationsPanel, ThreatOverviewCard)

---

## Phase 3 — Home Page + Results Page UI
*(To be filled by Claude Code after Phase 3 execution)*

---

## Phase 4 — Dashboard Page: Stats, Charts, Ticker
*(To be filled by Claude Code after Phase 4 execution)*

---

## Phase 5 — Reports Page + CSV Export
*(To be filled by Claude Code after Phase 5 execution)*

---

## Phase 6 — ML Pipeline: Training + Prediction + Endpoint
*(To be filled by Claude Code after Phase 6 execution)*

---

## Phase 7 — ML Insights Page + Feed Manager + Bulk Scanner
*(To be filled by Claude Code after Phase 7 execution)*

---

## Phase 8 — Polish: Skeletons, Error States, README, Final Cleanup
*(To be filled by Claude Code after Phase 8 execution)*
