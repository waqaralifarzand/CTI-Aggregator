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
**Date:** 2026-05-28
**Branch:** claude/vigilant-goldberg-uvyfZ
**Status:** ✅ Complete

### What Was Built
- backend/database.py — SQLAlchemy engine, SessionLocal, Base, get_db
- backend/models/ — ioc.py, scan_result.py, feed_result.py, feed_status.py, bulk_job.py
- backend/utils/response.py — ok() and err() envelope helpers
- backend/main.py — FastAPI app, CORS, all routers included, lifespan startup creates tables + seeds feed_status
- backend/routers/ — all 6 routers scaffolded (scan, dashboard, feeds, reports, ml, bulk)
- frontend/ — Vite + React 18 scaffolded via create-vite (React 19 used, compatible)
- frontend/src/index.css — all CSS variables, shimmer animation, marquee, scrollbar
- frontend/src/App.jsx — React Router v6 with all 7 routes
- frontend/src/api/client.js — Axios instance with all API call functions
- frontend/src/components/layout/ — Sidebar, PageWrapper, TopBar
- frontend/src/components/shared/ — SeverityBadge, CopyButton, ShareButton, LoadingSkeleton, EmptyState, ErrorState
- .gitignore — covers .env, *.db, *.pkl, __pycache__, node_modules, dist

### What Works
- GET /api/health → {status: ok, db: connected}
- DB tables auto-created on startup
- Feed status rows seeded for otx/urlhaus/malwarebazaar
- Frontend builds with no errors (npm run build ✓)
- All 7 routes render without console errors

### Known Issues
- React 19 was installed (package.json shows ^19.2.6) rather than 18 — fully compatible, no breaking changes for this app

---

## Phase 2 — Feed Integration: IoC Detection + OTX + Abuse.ch + Scan Endpoint
**Date:** 2026-05-28
**Branch:** claude/vigilant-goldberg-uvyfZ
**Status:** ✅ Complete

### What Was Built
- backend/services/ioc_detector.py — detect_type() with IPv4/IPv6/MD5/SHA256/SHA1/domain patterns
- backend/services/otx_service.py — async query_otx() with OTX_API_KEY, type mapping, graceful 404/error handling
- backend/services/abusech_service.py — async query_urlhaus() and query_malwarebazaar()
- backend/services/geo_service.py — async query_geo() via ip-api.com
- backend/services/whois_service.py — query_whois() using python-whois with full exception wrapping
- backend/utils/severity.py — compute_score(), score_to_severity(), generate_recommendations()
- backend/services/aggregator_service.py — run_scan() orchestrating all services with asyncio.gather
- backend/services/ml_service.py — predict_severity(), get_metrics(), get_feature_importance()
- backend/routers/scan.py — POST /api/scan, GET /api/scan/{scan_id}, GET /api/scans/recent
- backend/schemas/scan.py — ScanRequest, ScanResponse, ScanSummary, FeedResultItem
- backend/ml/features.py — extract_features() 10-feature vector
- backend/ml/trainer.py — train_model() with RF classifier, joblib save, metrics.json output

### What Works
- POST /api/scan accepts IP/domain/hash, routes to correct services
- DB writes: iocs, scan_results, feed_results all populated
- GET /api/scan/{scan_id} retrieves by UUID
- GET /api/scans/recent returns last N scans with IoC join

---

## Phase 3 — Home Page + Results Page UI
**Date:** 2026-05-28
**Branch:** claude/vigilant-goldberg-uvyfZ
**Status:** ✅ Complete

### What Was Built
- frontend/src/hooks/useScan.js — submitScan(), loading/error/scanId state
- frontend/src/components/scanner/ScanBar.jsx — hero input with client-side type detection
- frontend/src/components/scanner/IocTypeBadge.jsx — colored type pill
- frontend/src/components/scanner/ScanningState.jsx — animated loading state
- frontend/src/components/results/ThreatOverviewCard.jsx — score circle, severity badge, ML prediction
- frontend/src/components/results/OTXPanel.jsx — collapsible, pulse count, threat tags, categories
- frontend/src/components/results/AbuseChPanel.jsx — URLhaus + MalwareBazaar sub-sections
- frontend/src/components/results/BlacklistPanel.jsx — grid of blacklist source statuses
- frontend/src/components/results/MLPredictionPanel.jsx — confidence progress bar
- frontend/src/components/results/GeoPanel.jsx — IP-only conditional geo data
- frontend/src/components/results/WhoisPanel.jsx — domain-only conditional WHOIS
- frontend/src/components/results/RecommendationsPanel.jsx — numbered analyst action list
- frontend/src/pages/Home.jsx — hero scanner with IoC type cards below
- frontend/src/pages/Results.jsx — full scan result page with all panels

### What Works
- Full scan flow: type → scan → navigate to /results/{scanId}
- GeoPanel only renders for ip type, WhoisPanel only for domain type
- All panels use CSS variables, no hardcoded hex

---

## Phase 4 — Dashboard Page: Stats, Charts, Ticker
**Date:** 2026-05-28
**Branch:** claude/vigilant-goldberg-uvyfZ
**Status:** ✅ Complete

### What Was Built
- backend/routers/dashboard.py — stats, activity, severity-breakdown, ioc-breakdown, ticker endpoints
- backend/routers/feeds.py — GET /api/feeds, POST /api/feeds/{name}/refresh
- backend/schemas/dashboard.py — DashboardStats, ActivityPoint, TickerItem, SeverityCount, IocTypeCount
- frontend/src/hooks/useDashboard.js — parallel fetch of all dashboard data, progressive loading
- frontend/src/components/dashboard/StatCard.jsx — metric card with icon
- frontend/src/components/dashboard/SeverityDonut.jsx — Recharts PieChart with innerRadius
- frontend/src/components/dashboard/IocTypeBar.jsx — Recharts BarChart cyan bars
- frontend/src/components/dashboard/ActivityLine.jsx — Recharts LineChart dual lines
- frontend/src/components/dashboard/RecentScansTable.jsx — last 10 scans with links
- frontend/src/components/dashboard/FeedHealthWidget.jsx — feed status pill + last synced
- frontend/src/components/dashboard/LiveTicker.jsx — marquee animation, polls every 30s
- frontend/src/pages/Dashboard.jsx — full dashboard layout

### What Works
- All 5 dashboard API endpoints return real data from DB
- Charts render with real data after seeding
- LiveTicker scrolls and polls correctly
- Feed health shows correct status

---

## Phase 5 — Reports Page + CSV Export
**Date:** 2026-05-28
**Branch:** claude/vigilant-goldberg-uvyfZ
**Status:** ✅ Complete

### What Was Built
- backend/routers/reports.py — GET /api/reports (paginated, filtered), GET /api/reports/export (CSV StreamingResponse)
- backend/schemas/reports.py — ReportRow, ReportFilter, ReportResponse Pydantic v2 models
- frontend/src/hooks/useReports.js — full filter state, debounced search (300ms), exportCSV() with blob download
- frontend/src/components/reports/FilterBar.jsx — severity/ioc_type/date/search controls + Clear button
- frontend/src/components/reports/ReportsTable.jsx — sticky header, row hover, CopyButton inline, relative timestamps, pagination controls
- frontend/src/components/reports/ExportButton.jsx — download icon, exporting spinner state
- frontend/src/pages/Reports.jsx — Scan History title + ExportButton + FilterBar + ReportsTable
- 26 test scan_results seeded in DB for pagination testing

### What Works (verified with curl)
- GET /api/reports?page=1&limit=5 → total=26, 5 results
- GET /api/reports?page=2&limit=5 → page 2 returns next 5 results
- GET /api/reports?severity=low&search=8.8 → filtered total=1
- GET /api/reports/export → CSV with correct columns, 27 lines (header + 26 rows)
- CSV export respects active filters
- Frontend builds with no errors (npm run build ✓)
- All 7 routes render without console errors

### Known Issues
- None

### Mid-Execution Decisions
- Built Phases 1-5 in single session since no prior code existed (SCRATCHPAD was empty)
- Used React 19 (installed by Vite template) instead of 18 — fully API-compatible for this app
- Tailwind CSS v4 with @tailwindcss/vite plugin used (what Vite template installed)

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- Phase 6: ML Pipeline — build backend/ml/trainer.py full training loop, integrate ml_service into aggregator_service.run_scan(), implement GET /api/ml/metrics and POST /api/ml/train endpoints. Frontend: MLInsights page (MetricCard × 4, FeatureImportanceChart, RetrainButton) is already scaffolded at frontend/src/pages/MLInsights.jsx — just wire to real data.

---

## Phase 6 — ML Pipeline: Training + Prediction + Endpoint
*(To be filled by Claude Code after Phase 6 execution)*

---

## Phase 7 — ML Insights Page + Feed Manager + Bulk Scanner
*(To be filled by Claude Code after Phase 7 execution)*

---

## Phase 8 — Polish: Skeletons, Error States, README, Final Cleanup
*(To be filled by Claude Code after Phase 8 execution)*
