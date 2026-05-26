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
*(To be filled by Claude Code after Phase 2 execution)*

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
