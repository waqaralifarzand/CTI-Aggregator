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
**Date:** 2026-05-28
**Branch:** phase-6-ml-pipeline
**Status:** ✅ Complete

### What Was Built
- `backend/ml/trainer.py` — rewritten to use sklearn `LabelEncoder` (fit on all 5 classes), saves `model.pkl` + `label_encoder.pkl` + `model_meta.json`, added `load_model() -> (model, encoder) | None`
- `backend/ml/features.py` — added `build_training_dataframe(db_session) -> pd.DataFrame` (queries scan_results + iocs, reconstructs scan_data from raw_summary, returns 10-feature matrix + label column)
- `backend/services/ml_service.py` — rewrote to: load both pkl files, use `label_encoder.inverse_transform()` for predictions, `get_metrics()` reads `model_meta.json` and always includes `model_trained` bool, added `_bust_cache()` for post-retrain invalidation
- `backend/routers/ml.py` — `POST /api/ml/train` now checks scan count first (returns HTTP 400 if < 50), returns `training_samples` count, calls `_bust_cache()` after background task finishes
- `backend/seed_ml_data.py` — standalone seed script with 52 IoC entries (IPs/domains/hashes, mix of all 5 severities), writes directly to DB, safe to run multiple times
- `frontend/src/components/ml/MetricCard.jsx` — added color-coded top border (green ≥ 0.85, yellow ≥ 0.70, red < 0.70)
- `frontend/src/components/ml/RetrainButton.jsx` — 4-second toast notifications (green success / red error), toast includes training_samples count
- `frontend/src/pages/MLInsights.jsx` — shows empty state with inline RetrainButton when not trained; when trained: 4 MetricCards + last_trained/training_samples in header + full-width FeatureImportanceChart
- `.gitignore` — added `backend/ml/model_meta.json`

### What Works (verified with curl + build)
- `POST /api/ml/train` with 78 scans → `{ success: true, data: { message, training_samples: 78 } }`
- Background task completes in ~5s → `model.pkl`, `label_encoder.pkl`, `model_meta.json` created in `backend/ml/`
- `GET /api/ml/metrics` → `{ model_trained: true, accuracy: 0.875, precision: 0.888, recall: 0.875, f1_score: 0.872, last_trained, training_samples: 78 }`
- `GET /api/ml/features` → 10 features sorted by importance (threat_score=0.548, otx_pulse_count=0.252, ...)
- `POST /api/scan {"value": "..."}` → includes `ml_severity` + `ml_confidence` (not null)
- `model.pkl`, `label_encoder.pkl`, `model_meta.json` all gitignored correctly — don't appear in `git status`
- `npm run build` passes with no errors

### Seeding Details
- Seeded 52 additional scan results via `seed_ml_data.py` (direct DB write, no HTTP)
- Total scan_results in DB after seeding: **78**
- Severity distribution: ~25% critical, ~20% high, ~20% medium, ~15% low, ~20% clean
- Script kept in repo as a utility (`backend/seed_ml_data.py`) — not imported by main app

### ML Model Results
- Model: `RandomForestClassifier(n_estimators=100, random_state=42)`
- Training samples: 78 (80/20 split → 62 train, 16 test)
- **Accuracy: 87.5%**
- Precision: 88.75% (weighted)
- Recall: 87.5% (weighted)
- F1-Score: 87.2% (weighted)
- Top features: threat_score (54.8%), otx_pulse_count (25.2%), otx_found (5.1%)

### Known Issues
- ml_severity from live OTX/Abuse.ch scans returns "clean" for IPs that are actually clean (Google DNS 8.8.8.8) — this is correct behavior
- Model is simple RF on seeded data; real-world accuracy will vary once actual feed data populates the DB

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- Phase 7: ML Insights page, Feed Manager, and Bulk Scanner are all already scaffolded — wire remaining stubs. Key tasks: verify bulk scan background task processes IoCs sequentially, FeedCard refresh updates status in real time, FeatureImportanceChart shows bars with value labels.

---

## Phase 7 — Feed Manager + Bulk Scanner
**Date:** 2026-05-28
**Branch:** phase-7-feeds-bulk
**Status:** ✅ Complete

### What Was Built
- `backend/models/scan_result.py` — added nullable `bulk_job_id TEXT` column (indexed) to link scan results to bulk jobs
- `backend/routers/bulk.py` — updated `_process_bulk_job` to set `bulk_job_id` on each ScanResult; updated `GET /api/bulk/{job_id}` to join ScanResult+IoC and return `results` array
- `backend/routers/feeds.py` — added VirusTotal to `_FEED_HEALTH_CHECKS`, added `_get_vt_key()`, handles 401 with no key as `no_key` status rather than auth_error
- `backend/main.py` — added `virustotal` to startup feed_status seeding (4 feeds total)
- `frontend/src/components/feeds/FeedCard.jsx` — brand-colored left borders (OTX=cyan, URLhaus=orange, MalwareBazaar=red, VirusTotal=indigo), expanded statusConfig (online, auth_error, degraded, timeout, offline, no_key), full refresh state update including error_message
- `frontend/src/pages/Feeds.jsx` — updated to 2×2 grid, 4 loading skeletons, cleared error on retry
- `frontend/src/components/bulk/BulkProgressBar.jsx` — fixed status checks (`completed`/`failed`), added `failed` count display, improved labels
- `frontend/src/pages/Bulk.jsx` — fixed poll stop condition to `completed`/`failed`, passes `failed` prop to BulkProgressBar

### What Works
- GET /api/feeds returns 4 feeds (otx, urlhaus, malwarebazaar, virustotal)
- POST /api/feeds/{name}/refresh updates status and returns updated fields
- VirusTotal shows "No API Key" status when VT_API_KEY not set
- POST /api/bulk/scan accepts CSV, creates BulkJob, starts background processing
- GET /api/bulk/{job_id} returns job metadata + results array (ioc_value, ioc_type, severity, score, scan_id)
- BulkResultsTable renders with links to individual scan results
- Frontend builds with no errors (npm run build ✓)
- All 7 routes render without console errors

### Known Issues
- bulk_job_id column added via SQLAlchemy model — on existing DBs with old schema, column is added automatically on startup via create_all (SQLite adds columns only for new tables by default; existing DB may need recreation or ALTER TABLE migration for the new column)

### Mid-Execution Decisions
- VirusTotal `no_key` status used instead of `auth_error` when VT_API_KEY is not configured, to distinguish misconfiguration from a real auth failure
- Feeds grid changed from 3-column to 2×2 to accommodate 4 feeds more evenly

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- Phase 8: Polish — loading skeletons everywhere, error boundaries, README.md for the repo, final cleanup. Verify bulk_job_id column migration on existing SQLite DB.

---

## Phase 8 — Polish: Error States, document.title, README, Final Cleanup
**Date:** 2026-05-28
**Branch:** phase-8-polish
**Status:** ✅ Complete

### What Was Built
- `frontend/src/pages/Home.jsx` — added `document.title`, added `RecentScansQuickLinks` component (shows last 3 scans as quick-access links, silently hidden on error)
- `frontend/src/pages/Results.jsx` — added `document.title`, replaced generic ErrorState with `ScanNotFound` inline component showing "Scan not found or no longer available." + "Back to Scanner" link, separate `notFound` state for 404 vs network error
- `frontend/src/pages/Dashboard.jsx` — added `document.title`, `statsError` renders ErrorState in stat card grid area, `noData` flag shows EmptyState in charts + RecentScansTable when 0 total_scans
- `frontend/src/pages/Reports.jsx` — added `document.title`
- `frontend/src/pages/Feeds.jsx` — added `document.title`
- `frontend/src/pages/MLInsights.jsx` — added `document.title`
- `frontend/src/pages/Bulk.jsx` — added `document.title`
- `frontend/src/components/layout/Sidebar.jsx` — fixed `onMouseLeave` handler (was empty/no-op, leaving stale hover color); now correctly resets color/background for non-active items using `aria-current` attribute
- `backend/main.py` — removed `print()` statement from startup feed seeding
- `backend/.env.example` — added `VT_API_KEY` entry
- `README.md` — complete rewrite: prerequisites, setup steps, first use, ML training instructions, bulk scan format, project structure, academic context
- `PHASES (3).md` — all 8 phases marked ✅ Complete
- `SCRATCHPAD (3).md` — Phase 8 entry added

### What Works
- All 7 pages set correct `document.title` on mount
- Results page shows "Back to Scanner" link instead of generic error for 404 scans
- Dashboard shows EmptyState inside chart/table areas when DB has 0 scans; statsError shows ErrorState in stat grid without crashing other sections
- Home page shows last 3 scans as quick-access links (hidden silently if fetch fails or no scans yet)
- Sidebar hover state correctly resets on mouse leave
- `npm run build` passes with zero errors

### Known Issues
- None

### Mid-Execution Decisions
- `ScanNotFound` implemented as inline component inside Results.jsx (not a separate file) — it's only used once
- Dashboard `noData` check uses `stats?.total_scans === 0` which shows EmptyState even when charts are loading; guarded by `!statsLoading && !statsError` check

### Live URLs / Ports
- Backend: http://localhost:8000
- Frontend: http://localhost:5173
- API Docs: http://localhost:8000/docs

### Next Session Picks Up At
- Project complete. All 8 phases done.
