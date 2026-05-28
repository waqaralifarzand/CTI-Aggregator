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
**Date:** 2026-05-26
**Branch:** claude/trusting-dirac-V4y3q
**Status:** ✅ Complete

### What Was Built
- `frontend/src/components/shared/SeverityBadge.jsx` — pill badge, 5 variants (critical/high/medium/low/clean), CSS variable colors, 15% opacity bg, 3 sizes
- `frontend/src/components/shared/CopyButton.jsx` — clipboard copy, 2s "Copied!" confirmation with checkmark
- `frontend/src/components/shared/ShareButton.jsx` — copies current URL, 2s confirmation
- `frontend/src/components/shared/LoadingSkeleton.jsx` — shimmer block (height/width props) + SkeletonPanel composite
- `frontend/src/components/shared/EmptyState.jsx` — icon + title + description centered layout
- `frontend/src/components/shared/ErrorState.jsx` — error icon + message + optional retry button
- `frontend/src/components/scanner/IocTypeBadge.jsx` — client-side type detection (no API), colored pill (IP=blue, domain=cyan, hashes=yellow); exports detectTypeClient
- `frontend/src/components/scanner/ScanningState.jsx` — animated spinner + "Scanning…" + IoC value
- `frontend/src/hooks/useScan.js` — iocValue, loading, error state + scan() function
- `frontend/src/components/results/ThreatOverviewCard.jsx` — SVG score ring (colored by severity), threat score, ML status, scanned timestamp
- `frontend/src/components/results/OTXPanel.jsx` — collapsible, OTX pulses/tags/categories, found/not-found states
- `frontend/src/components/results/AbuseChPanel.jsx` — URLhaus + MalwareBazaar sub-sections, applicable/N-A handling
- `frontend/src/components/results/VirusTotalPanel.jsx` — detection ratio with progress bar, flagged engine list
- `frontend/src/components/results/BlacklistPanel.jsx` — grid of 4 sources, clean/flagged status chips
- `frontend/src/components/results/MLPredictionPanel.jsx` — confidence progress bar, "not trained" state
- `frontend/src/components/results/GeoPanel.jsx` — country flag emoji, city/ISP/ASN grid; only renders for ip type
- `frontend/src/components/results/WhoisPanel.jsx` — registrar/dates/nameservers; only renders for domain type with data
- `frontend/src/components/results/RecommendationsPanel.jsx` — cyan numbered circles, analyst bullet list
- `frontend/src/pages/Home.jsx` — full rewrite: hero, ScanBar with mono font + cyan focus border, IocTypeBadge below input, scan button with spinner, recent 3 scans as quick-links, error inline display
- `frontend/src/pages/Results.jsx` — full rewrite: sticky topbar (IoC value + badges + copy/share), 9 result panels with staggered fade-in, LoadingSkeleton blocks, ErrorState for 404/failures
- `frontend/src/index.css` — added `@keyframes spin` for button/loader spinner

### What Works
- ✅ Build clean: npm run build — 0 errors, 97 modules, 293kB JS
- ✅ Frontend HTTP 200 at localhost:5173
- ✅ Backend: POST /api/scan (IP/hash/domain) → HTTP 200
- ✅ GET /api/scan/{scan_id} → HTTP 200 with stored result
- ✅ GET /api/scan/invalid-id → HTTP 404 (ErrorState shown on Results page)
- ✅ GET /api/scans/recent?limit=3 → 3 most recent
- ✅ All colors via CSS variables — zero hardcoded hex in new component files
- ✅ JetBrains Mono on all IoC values/hashes/IPs
- ✅ GeoPanel only renders for ip type; WhoisPanel only for domain type with data
- ✅ OTXPanel collapsible; auto-expanded if found=true

### What's Pending / Skipped
- Live scan flow (type → scan → navigate to results) requires a browser test; sandbox network blocks external API calls so severity will show "clean" until run locally with real API keys
- GeoPanel and WhoisPanel will show real data locally (ip-api.com and WHOIS blocked in sandbox)

### Known Issues
- None

### Mid-Execution Decisions
- Branch: same `claude/trusting-dirac-V4y3q` per system constraint
- `useAnimStyle` defined as regular function (not a hook) inside Results.jsx since it's just returning a static style object — no state or effects, so no React rules violation
- IocTypeBadge uses CSS variable references in template literals (`${color}22`, `${color}44`) for bg/border opacity since CSS variables can't be directly alpha-modified in all contexts
- ScanningState spinner uses inline `<style>` tag for `@keyframes spin` as backup — global one now added to index.css

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- Phase 4: Dashboard page — LiveTicker, StatCard×4, SeverityDonut, IocTypeBar, ActivityLine, FeedHealthWidget, RecentScansTable. Backend: implement all 5 dashboard endpoints + feeds router GET/refresh.

---

## Phase 4 — Dashboard Page: Stats, Charts, Ticker
**Date:** 2026-05-26
**Branch:** claude/trusting-dirac-V4y3q
**Status:** ✅ Complete

### What Was Built
**Backend:**
- `backend/routers/dashboard.py` — full implementation of all 5 endpoints:
  - GET /api/dashboard/stats — total/threats/critical/clean counts via SQLAlchemy aggregates
  - GET /api/dashboard/activity?days=N — per-day scans+threats for last N days using datetime window queries
  - GET /api/dashboard/severity-breakdown — all 5 severity levels including zero-count levels
  - GET /api/dashboard/ioc-breakdown — IoC type counts from iocs table
  - GET /api/dashboard/ticker — high/critical scan_results with OTX tags from feed_results join
- Seeded 10 varied-severity rows (critical×2, high×4, medium×2, low×1, clean×1) spread across last 7 days

**Frontend:**
- `frontend/src/hooks/useDashboard.js` — parallel fetch of 7 data sections via individual Promises; each has own loading/error flag; exposes refresh()
- `frontend/src/components/dashboard/StatCard.jsx` — icon + label + large value + optional subtitle; left accent border via accentColor prop
- `frontend/src/components/dashboard/SeverityDonut.jsx` — Recharts PieChart with innerRadius; SVG center label showing total; custom legend with swatch + label + count; all colors via HEX constants mapped to severity CSS var values
- `frontend/src/components/dashboard/IocTypeBar.jsx` — Recharts BarChart; cyan bars (#06b6d4); custom tooltip; TYPE_LABELS mapping
- `frontend/src/components/dashboard/ActivityLine.jsx` — Recharts LineChart; two lines (scans=cyan, threats=orange); monotone curve; custom tooltip; MM-DD date labels
- `frontend/src/components/dashboard/FeedHealthWidget.jsx` — status pill (active/error/syncing/unknown); relativeTime(); Refresh button triggers POST /api/feeds/{name}/refresh; local state update on response; mini spinner
- `frontend/src/components/dashboard/RecentScansTable.jsx` — 10-row table with JetBrains Mono IoC values; SeverityBadge; relativeTime; LoadingSkeleton rows while loading; EmptyState if empty; link to /results/{scan_id}
- `frontend/src/components/dashboard/LiveTicker.jsx` — horizontal marquee; "⚠ LIVE THREATS" left label; doubled items for seamless loop; pause on hover; 30s polling; hidden if no high/critical items; navigate on click
- `frontend/src/pages/Dashboard.jsx` — full rewrite: LiveTicker (full width), page header + Refresh button, 4 StatCards, 3-col chart row, 2-col bottom (FeedHealthWidget 2×2 + RecentScansTable)
- `frontend/src/index.css` — added `@keyframes marquee`

### What Works
- ✅ GET /api/dashboard/stats → {total_scans:20, threats_found:9, critical_alerts:2, clean_scans:11}
- ✅ GET /api/dashboard/severity-breakdown → all 5 levels with counts
- ✅ GET /api/dashboard/ioc-breakdown → domain:8, hash_md5:2, ip:6
- ✅ GET /api/dashboard/activity?days=3 → per-day data including today
- ✅ GET /api/dashboard/ticker → 5 high/critical items with tags
- ✅ GET /api/feeds → 4 feeds (otx/urlhaus/malwarebazaar/virustotal)
- ✅ POST /api/feeds/urlhaus/refresh → returns {status:error, message:'Feed check failed: HTTP 403'} (network blocked in sandbox — endpoint works correctly)
- ✅ Frontend build: 0 errors, 665 modules
- ✅ LiveTicker: items present in DB (visible), hides when no high/critical
- ✅ All chart colors via HEX constants mapped from CSS variables (Recharts can't resolve CSS vars at paint time)
- ✅ RecentScansTable rows link to /results/{scan_id}

### What's Pending / Skipped
- Feed refresh pings return 'error' in sandbox (network blocked) — expected; widget correctly shows error status and message
- No real-time SSE/WebSocket; ticker polls every 30s as specified

### Known Issues
- None

### Mid-Execution Decisions
- Branch: same `claude/trusting-dirac-V4y3q` per system constraint
- Recharts can't use CSS var() values in `fill`/`stroke` props directly — used hardcoded HEX constants matching the CSS variables. These are the same values as the CSS vars so the visual result is identical
- Seeded 10 test rows with varied severities so charts have something meaningful to display
- Activity query uses per-day datetime windows (UTC) rather than SQLite date() function to avoid timezone issues
- SeverityDonut filters zero-count severities from Recharts data (they'd show as invisible 0-width segments) but includes them all in legend only if count > 0

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- Phase 5: Reports page + CSV export — implement GET /api/reports (paginated, filterable), GET /api/reports/export (CSV), FilterBar, ReportsTable, ExportButton, useReports hook

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
