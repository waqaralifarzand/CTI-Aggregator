# PHASES.md — CTI Aggregator Execution Roadmap

> Each phase = one focused Claude Code session.
> No phase begins until the previous one is approved in the planning chat.
> Claude Code reads CLAUDE.md + ARCHITECTURE.md + this file at the start of every session.

---

## Status Tracker

| Phase | Title | Status |
|---|---|---|
| Phase 1 | Repo Setup — Backend + Frontend Skeleton | ✅ Complete |
| Phase 2 | Feed Integration — IoC Detection + OTX + Abuse.ch + Scan Endpoint | ✅ Complete |
| Phase 3 | Home Page + Results Page UI | ✅ Complete |
| Phase 4 | Dashboard Page — Stats, Charts, Ticker | ✅ Complete |
| Phase 5 | Reports Page + CSV Export | ✅ Complete |
| Phase 6 | ML Pipeline — Training + Prediction + Endpoint | ✅ Complete |
| Phase 7 | ML Insights + Feed Manager + Bulk Scanner | ✅ Complete |
| Phase 8 | Polish — Skeletons, Error States, README, Final Cleanup | ✅ Complete |

---

## Phase 1 — Repo Setup: Backend + Frontend Skeleton

**Goal:** Both apps run locally with no errors. Backend returns a health check. Frontend renders the sidebar and an empty home page. DB tables are created.

### Tasks

**Repo root:**
- [ ] Create `.gitignore` (ignore `__pycache__`, `.env`, `*.pkl`, `node_modules`, `*.db`)
- [ ] Create `README.md` with placeholder run instructions

**Backend (`/backend`):**
- [ ] Create `requirements.txt` with all dependencies from ARCHITECTURE.md tech stack table
- [ ] Create `.env.example` with placeholder values
- [ ] Create `database.py` — SQLAlchemy engine, `SessionLocal`, `Base`, `get_db` dependency
- [ ] Create all 5 DB models in `models/`: `ioc.py`, `scan_result.py`, `feed_result.py`, `feed_status.py`, `bulk_job.py`
- [ ] Create `utils/response.py` — `ok(data)` and `err(message)` helpers returning standard envelope
- [ ] Create `main.py` — FastAPI app, CORS middleware (allow `CORS_ORIGINS` from `.env`), include all routers (stubbed), create all DB tables on startup
- [ ] Create stub routers in `routers/`: `scan.py`, `bulk.py`, `feeds.py`, `reports.py`, `ml.py`, `dashboard.py` — each returns `{"status": "not implemented"}` placeholder
- [ ] Add `GET /api/health` endpoint returning `{"status": "ok", "db": "connected"}`
- [ ] Verify: `uvicorn main:app --reload` starts without errors

**Frontend (`/frontend`):**
- [ ] Scaffold with `npm create vite@latest frontend -- --template react`
- [ ] Install dependencies: `tailwindcss`, `axios`, `react-router-dom`, `recharts`, `react-dropzone`
- [ ] Configure Tailwind: `tailwind.config.js` + `postcss.config.js`
- [ ] Create `src/index.css` — all CSS variables from CLAUDE.md design system, base reset, import Google Fonts (DM Sans + JetBrains Mono)
- [ ] Create `src/api/client.js` — Axios instance with `baseURL` from `VITE_API_BASE_URL`, stub functions for every API endpoint
- [ ] Create `src/components/layout/Sidebar.jsx` — fixed left nav (240px), logo text "CTI Aggregator", nav links to all 7 routes, active state styling using CSS variables
- [ ] Create `src/components/layout/PageWrapper.jsx` — consistent padding wrapper
- [ ] Create `src/App.jsx` — React Router v6 routes for all 7 pages, Sidebar always visible
- [ ] Create all 7 page files in `src/pages/` as empty stubs returning `<PageWrapper><h1>PageName</h1></PageWrapper>`
- [ ] Create `.env` with `VITE_API_BASE_URL=http://localhost:8000`
- [ ] Verify: `npm run dev` starts, sidebar visible, all nav links render without errors

### Acceptance Criteria
- `GET http://localhost:8000/api/health` returns `{ "success": true, "data": { "status": "ok", "db": "connected" } }`
- `http://localhost:5173` renders the sidebar with all nav links
- Clicking each nav link renders the correct stub page with no console errors
- No TypeScript errors, no Python import errors

### Done Definition
Both servers running, sidebar navigable, DB tables created, zero errors in console or terminal.

---

## Phase 2 — Feed Integration: IoC Detection + OTX + Abuse.ch + Scan Endpoint

**Goal:** `POST /api/scan` works end-to-end. Submitting a real IP/domain/hash queries OTX and Abuse.ch, scores the result, writes to DB, and returns a full structured response.

### Tasks

**IoC Detection (`backend/services/ioc_detector.py`):**
- [ ] Implement `detect_type(value: str) -> str` using the detection table in ARCHITECTURE.md
- [ ] Handle edge cases: strip whitespace, lowercase before matching, handle IPv6
- [ ] Return one of: `ip`, `domain`, `hash_md5`, `hash_sha256`, `hash_sha1`
- [ ] Raise `ValueError` for unrecognized input

**OTX Service (`backend/services/otx_service.py`):**
- [ ] Implement `query_otx(ioc_value: str, ioc_type: str) -> dict` using `httpx.AsyncClient`
- [ ] Use `OTX_API_KEY` from env, endpoint: `https://otx.alienvault.com/api/v1/indicators/{type}/{value}/general`
- [ ] Map ioc_type to OTX type: `ip` → `IPv4`, `domain` → `domain`, `hash_md5`/`hash_sha256` → `file`
- [ ] Return normalized dict: `{ found, pulse_count, threat_tags, categories, country, raw_data }`
- [ ] Handle 404 (IoC not found) gracefully — return `{ found: false }`
- [ ] Handle API errors — return `{ found: false, error: message }`

**Abuse.ch Services (`backend/services/abusech_service.py`):**
- [ ] Implement `query_urlhaus(ioc_value: str, ioc_type: str) -> dict` — POST to `https://urlhaus-api.abuse.ch/v1/url/` or `/host/`
- [ ] Implement `query_malwarebazaar(ioc_value: str, ioc_type: str) -> dict` — POST to `https://mb-api.abuse.ch/api/v1/` with `query=get_info`
- [ ] Only query URLhaus for `ip`/`domain`, only MalwareBazaar for hashes
- [ ] Return normalized dict: `{ found, url_count, tags, raw_data }` for URLhaus; `{ found, file_type, signature, tags, raw_data }` for MalwareBazaar
- [ ] Handle gracefully when IoC type is not applicable for that feed

**Geo Service (`backend/services/geo_service.py`):**
- [ ] Implement `query_geo(ip: str) -> dict` — GET `http://ip-api.com/json/{ip}`
- [ ] Only called when `ioc_type == "ip"`
- [ ] Return normalized dict: `{ country, country_code, region, city, isp, asn }`
- [ ] Handle API failure gracefully — return `None`

**WHOIS Service (`backend/services/whois_service.py`):**
- [ ] Implement `query_whois(domain: str) -> dict` using `python-whois`
- [ ] Only called when `ioc_type == "domain"`
- [ ] Return normalized dict: `{ registrar, creation_date, expiration_date, name_servers, status }`
- [ ] Wrap in try/except — WHOIS fails often, return `None` on any error

**Severity Scoring (`backend/utils/severity.py`):**
- [ ] Implement `compute_score(feed_results: dict) -> int` using the point table in ARCHITECTURE.md
- [ ] Implement `score_to_severity(score: int) -> str` using the score → label table
- [ ] Implement `generate_recommendations(severity: str, feed_results: dict) -> list[str]` — returns 2–3 analyst action strings based on what was found

**Aggregator Service (`backend/services/aggregator_service.py`):**
- [ ] Implement `run_scan(ioc_value: str) -> dict` — orchestrates all service calls concurrently using `asyncio.gather`
- [ ] Detects type first, then calls appropriate services in parallel
- [ ] Computes threat_score and overall_severity
- [ ] Returns full response dict matching the `ScanResponse` shape in ARCHITECTURE.md

**Scan Router (`backend/routers/scan.py`):**
- [ ] Implement `POST /api/scan` — validate input, call aggregator, write IoC + ScanResult + FeedResults to DB, return response
- [ ] If same IoC already in DB: increment `scan_count`, update `last_seen`, create new `scan_result` row
- [ ] Implement `GET /api/scan/{scan_id}` — fetch by UUID, return same ScanResponse shape
- [ ] Implement `GET /api/scans/recent?limit=10`

**Pydantic Schemas (`backend/schemas/scan.py`):**
- [ ] Define `ScanRequest`, `ScanResponse`, `FeedResultItem`, `GeoData`, `WhoisData`, `BlacklistStatus`

### Acceptance Criteria
- `POST /api/scan {"value": "8.8.8.8"}` returns full response with OTX data, geo data, severity, threat_score, scan_id
- `POST /api/scan {"value": "44d88612fea8a8f36de82e1278abb02f"}` (EICAR MD5) returns MalwareBazaar hit
- `POST /api/scan {"value": "malware.example.com"}` returns domain scan with WHOIS
- `GET /api/scan/{scan_id}` returns same result
- All results written correctly to `iocs`, `scan_results`, `feed_results` tables
- Invalid input returns `{ success: false, error: "..." }` with HTTP 422

### Done Definition
Three test IoCs (IP, hash, domain) all return full structured results with no 500 errors.

---

## Phase 3 — Home Page + Results Page UI

**Goal:** The two most important pages look and work exactly like the design spec. Sucuri-inspired hero scanner on Home. Full result panels on Results. Design system fully applied.

### Tasks

**Shared Components:**
- [ ] `SeverityBadge.jsx` — pill component, 5 variants: critical/high/medium/low/clean using CSS severity variables
- [ ] `CopyButton.jsx` — icon button, copies text to clipboard, shows "Copied!" confirmation for 2s
- [ ] `ShareButton.jsx` — icon button, copies current URL to clipboard, shows confirmation
- [ ] `LoadingSkeleton.jsx` — animated shimmer placeholder, accepts `height` and `width` props
- [ ] `EmptyState.jsx` — centered icon + heading + subtext
- [ ] `ErrorState.jsx` — error icon + message + retry button callback prop

**Home Page (`src/pages/Home.jsx`):**
- [ ] Full-page dark layout (no sidebar content obscuring hero)
- [ ] Centered hero: project name "CTI Aggregator", one-line subtitle
- [ ] `ScanBar.jsx` — large input (JetBrains Mono font), cyan border on focus, placeholder: "Enter IP address, domain, or file hash..."
- [ ] `IocTypeBadge.jsx` — appears below input as user types, shows auto-detected type via debounced pattern match (client-side preview, not API call)
- [ ] Scan button: cyan background, "Scan" label, shows spinner on submit
- [ ] On submit: `POST /api/scan`, then navigate to `/results/{scan_id}`
- [ ] Error handling: show inline error below input if scan fails

**`useScan.js` hook:**
- [ ] `submitScan(value)` — calls API, manages loading/error state, returns scan_id on success

**Results Page (`src/pages/Results.jsx`):**
- [ ] Fetch scan by `scan_id` from URL param on mount
- [ ] Show `LoadingSkeleton` blocks while loading
- [ ] TopBar: IoC value (JetBrains Mono) + `CopyButton` + `ShareButton` + `SeverityBadge`
- [ ] "Scan another" link back to `/`

**Result Panel Components:**

- [ ] `ThreatOverviewCard.jsx` — large card at top: severity label, threat score (0–100 circular progress or large number), ML prediction + confidence, scanned timestamp
- [ ] `OTXPanel.jsx` — OTX logo/label, found/not-found status, pulse count, threat tags as small pills, categories list, country (if IP). Collapsed by default if `found: false`
- [ ] `AbuseChPanel.jsx` — two sub-sections: URLhaus and MalwareBazaar. Each shows found status, relevant details. Collapsed if both `found: false`
- [ ] `BlacklistPanel.jsx` — grid of blacklist sources with ✅ clean or 🔴 flagged status pills
- [ ] `MLPredictionPanel.jsx` — predicted severity label + confidence as a horizontal progress bar colored by severity. Shows "Model not trained yet" if no model
- [ ] `GeoPanel.jsx` — only renders if `ioc_type === "ip"`. Flag emoji + country, ISP, ASN in a clean grid
- [ ] `WhoisPanel.jsx` — only renders if `ioc_type === "domain"`. Registrar, creation date, expiry date
- [ ] `RecommendationsPanel.jsx` — numbered list of analyst action items, cyan accent bullets

### Acceptance Criteria
- Home page: typing a valid IP shows "IP Address" badge, typing a hash shows "File Hash" badge
- Submitting `8.8.8.8` navigates to `/results/{scan_id}` and renders all panels
- GeoPanel visible for IP, hidden for domain scan
- WhoisPanel visible for domain, hidden for IP scan
- Sharing the `/results/{scan_id}` URL directly in browser loads the result correctly
- All severity colors match the CSS variable definitions
- No hardcoded hex colors anywhere in components

### Done Definition
Full scan flow works: type → scan → results page with all applicable panels rendered correctly with real data.

---

## Phase 4 — Dashboard Page: Stats, Charts, Ticker

**Goal:** `/dashboard` is a live, data-driven overview. All 4 stat cards, 3 charts, live ticker, feed health widgets, and recent scans table — all pulling from real DB data.

### Tasks

**Backend — Dashboard Router (`backend/routers/dashboard.py`):**
- [ ] Implement `GET /api/dashboard/stats` — query DB for total scans, threats found (severity != clean), critical alerts, clean scans
- [ ] Implement `GET /api/dashboard/activity?days=7` — group scan_results by date for last N days
- [ ] Implement `GET /api/dashboard/severity-breakdown` — count scan_results grouped by overall_severity
- [ ] Implement `GET /api/dashboard/ioc-breakdown` — count iocs grouped by type
- [ ] Implement `GET /api/dashboard/ticker?limit=20` — latest scan_results where severity IN (high, critical), ordered by scanned_at DESC

**Backend — Feeds Router (`backend/routers/feeds.py`):**
- [ ] Implement `GET /api/feeds` — return all rows from `feed_status` table
- [ ] Implement `POST /api/feeds/{feed_name}/refresh` — make a test API call to the feed, update `feed_status` row with result
- [ ] On app startup in `main.py`: upsert initial rows into `feed_status` for `otx`, `urlhaus`, `malwarebazaar`

**Frontend — Dashboard Components:**

- [ ] `StatCard.jsx` — icon (SVG), label, large number value, optional delta/subtitle
- [ ] `SeverityDonut.jsx` — Recharts `PieChart` with `innerRadius`. Colors mapped from CSS severity variables. Custom legend below
- [ ] `IocTypeBar.jsx` — Recharts `BarChart`, one bar per IoC type, cyan fill
- [ ] `ActivityLine.jsx` — Recharts `LineChart`, two lines: total scans + threats, 7-day x-axis
- [ ] `RecentScansTable.jsx` — table with columns: IoC Value, Type, Severity, Score, Time, Link to results
- [ ] `FeedHealthWidget.jsx` — feed name, status pill (active=green, error=red, syncing=yellow), last synced time
- [ ] `LiveTicker.jsx` — horizontal scrolling banner using CSS `animation: marquee`. Shows latest high/critical IoCs. Clicking one navigates to its result. Pauses on hover. Polls `GET /api/dashboard/ticker` every 30 seconds

**`useDashboard.js` hook:**
- [ ] Fetch all dashboard data in parallel on mount
- [ ] Manage loading states per section so components render progressively

**Dashboard Page (`src/pages/Dashboard.jsx`):**
- [ ] LiveTicker at the very top (full width, above all cards)
- [ ] 4 StatCards in a row
- [ ] 3-column chart row: SeverityDonut, IocTypeBar, ActivityLine
- [ ] 2-column bottom row: FeedHealthWidget × 2 | RecentScansTable

### Acceptance Criteria
- After running 5+ scans in Phase 2/3, dashboard shows real counts
- All charts render with real data (not hardcoded)
- LiveTicker scrolls with real high/critical threats from DB
- Feed health widgets show correct status for OTX and Abuse.ch
- RecentScansTable rows link correctly to `/results/{scan_id}`
- Progressive loading — stat cards appear before charts finish loading

### Done Definition
Dashboard fully functional with real data. LiveTicker animating. All charts rendering. Feed health visible.

---

## Phase 5 — Reports Page + CSV Export

**Goal:** `/reports` is a filterable, searchable, exportable table of all historical scans.

### Tasks

**Backend — Reports Router (`backend/routers/reports.py`):**
- [ ] Implement `GET /api/reports` with full query params: `page`, `limit`, `severity`, `ioc_type`, `date_from`, `date_to`, `search`
- [ ] Build SQLAlchemy query dynamically based on which filters are present
- [ ] Return paginated response with `total`, `page`, `limit`, `results`
- [ ] Implement `GET /api/reports/export` — same filters, streams CSV response
- [ ] CSV uses `StreamingResponse` with `text/csv` content type
- [ ] CSV filename header: `Content-Disposition: attachment; filename=cti_report_{timestamp}.csv`
- [ ] CSV columns: `scan_id, ioc_value, ioc_type, overall_severity, threat_score, ml_severity, ml_confidence, scanned_at`

**Frontend — Reports Components:**

- [ ] `FilterBar.jsx` — row of filter controls:
  - Severity dropdown: All / Critical / High / Medium / Low / Clean
  - IoC Type dropdown: All / IP / Domain / MD5 Hash / SHA256 Hash
  - Date range: two `<input type="date">` fields (from / to)
  - Search input: text, queries `ioc_value` partial match
  - "Clear Filters" button resets all to default
- [ ] `ReportsTable.jsx` — full-width table:
  - Columns: IoC Value (JetBrains Mono + CopyButton), Type, Severity (SeverityBadge), Score, ML Severity, Scanned At, Actions (link to result)
  - Pagination controls: Previous / Next / page indicator
  - Empty state if no results match filters
- [ ] `ExportButton.jsx` — button triggers `GET /api/reports/export` with current active filters as query params, auto-downloads CSV

**`useReports.js` hook:**
- [ ] Manages filter state, page state
- [ ] Debounce search input (300ms)
- [ ] Re-fetches when any filter changes
- [ ] Handles loading and error states

**Reports Page (`src/pages/Reports.jsx`):**
- [ ] TopBar: "Scan History" title + `ExportButton` on the right
- [ ] FilterBar below TopBar
- [ ] ReportsTable fills remaining space

### Acceptance Criteria
- Filtering by severity shows only matching rows
- Searching "8.8.8" filters IoC values correctly
- Pagination works: 20 rows per page, page 2 loads next 20
- CSV export downloads a file with correct columns
- CSV respects active filters (filtered view exports filtered data)
- Clear Filters resets table to all results

### Done Definition
Reports page fully functional: filter, search, paginate, export — all working with real DB data.

---

## Phase 6 — ML Pipeline: Training + Prediction + Endpoint

**Goal:** Random Forest model trains from existing scan data, predicts severity for new scans, and reports metrics. ML prediction integrated into `POST /api/scan` response.

### Tasks

**Feature Extraction (`backend/ml/features.py`):**
- [ ] Implement `extract_features(scan_data: dict) -> list` — converts scan result dict into the 10-feature vector defined in ARCHITECTURE.md
- [ ] Handle missing feed data gracefully (default 0 for missing features)
- [ ] Add `build_training_dataframe(db_session) -> pd.DataFrame` — queries all scan_results + feed_results from DB, builds feature matrix + label column

**Trainer (`backend/ml/trainer.py`):**
- [ ] Implement `train_model(db_session) -> dict` — full training pipeline:
  1. Call `build_training_dataframe`
  2. Check minimum 50 samples — raise error if below
  3. Split 80/20 train/test
  4. Fit `RandomForestClassifier(n_estimators=100, random_state=42)`
  5. Evaluate on test set: accuracy, precision, recall, F1 (weighted)
  6. Save model to `backend/ml/model.pkl` using `joblib.dump`
  7. Save label encoder to `backend/ml/label_encoder.pkl`
  8. Return metrics dict
- [ ] Implement `load_model()` — loads model.pkl, returns None if file doesn't exist yet

**ML Service (`backend/services/ml_service.py`):**
- [ ] Implement `predict_severity(scan_data: dict) -> dict` — loads model, extracts features, returns `{ ml_severity, ml_confidence }`
- [ ] Return `{ ml_severity: None, ml_confidence: None }` if model not yet trained
- [ ] Implement `get_metrics() -> dict` — loads model metadata, returns the full metrics dict
- [ ] Implement `get_feature_importance() -> list` — returns feature names + importance scores sorted descending

**ML Router (`backend/routers/ml.py`):**
- [ ] Implement `GET /api/ml/metrics` — call `get_metrics()`, return response
- [ ] Implement `POST /api/ml/train` — run `train_model` as `BackgroundTasks` task, return immediate acknowledgement
- [ ] Implement `GET /api/ml/features` — return feature importance list

**Integrate ML into Scan (`backend/services/aggregator_service.py`):**
- [ ] After computing rule-based severity, call `ml_service.predict_severity()`
- [ ] Add `ml_severity` and `ml_confidence` to scan response and DB write

### Acceptance Criteria
- With fewer than 50 scan_results in DB: `POST /api/ml/train` returns `{ success: false, error: "Insufficient training data. Need at least 50 scans." }`
- After seeding DB with 50+ scans (mix of severities): `POST /api/ml/train` returns success
- `GET /api/ml/metrics` returns accuracy, precision, recall, F1 with values between 0 and 1
- `GET /api/ml/features` returns 10 features sorted by importance
- New `POST /api/scan` response includes `ml_severity` and `ml_confidence`
- If model not trained: `ml_severity: null` — no 500 errors

### Done Definition
Model trains from real data. New scans include ML prediction. Metrics endpoint returns real evaluation scores.

---

## Phase 7 — ML Insights Page + Feed Manager + Bulk Scanner

**Goal:** Three remaining pages fully functional. ML Insights visualizes model performance. Feed Manager shows live feed health. Bulk Scanner accepts a CSV and processes all IoCs.

### Tasks

**ML Insights Page (`src/pages/MLInsights.jsx`):**
- [ ] `MetricCard.jsx` — large number display: label + value formatted as percentage (e.g. "89.3%"). 4 instances: Accuracy, Precision, Recall, F1-Score
- [ ] `FeatureImportanceChart.jsx` — horizontal Recharts `BarChart`, feature names on Y axis, importance score on X, cyan bars, sorted descending
- [ ] `RetrainButton.jsx` — button triggers `POST /api/ml/train`, shows spinner, shows "Training started..." toast, disables itself during training
- [ ] Page shows "Model Not Trained Yet" EmptyState if `model_trained: false`
- [ ] Shows last trained date and number of training samples

**Feed Manager Page (`src/pages/Feeds.jsx`):**
- [ ] `FeedCard.jsx` — card per feed showing:
  - Feed name + icon/logo color
  - Status pill: Active (green) / Error (red) / Syncing (yellow)
  - Last synced: relative time (e.g. "2 hours ago")
  - Record count
  - Error message (if status is error)
  - "Refresh" button → `POST /api/feeds/{feed_name}/refresh` → updates card
- [ ] 3 FeedCards: AlienVault OTX, Abuse.ch URLhaus, Abuse.ch MalwareBazaar
- [ ] Refresh button shows spinner during call, updates status without page reload

**Bulk Scanner (`backend/routers/bulk.py`):**
- [ ] Implement `POST /api/bulk/scan`:
  - Accept `multipart/form-data` with CSV file
  - Parse CSV — one IoC per line, skip empty lines, strip whitespace
  - Validate max 500 IoCs per batch
  - Create `bulk_jobs` row with UUID job_id, set status to "running"
  - Launch background task: iterate IoCs, call `aggregator_service.run_scan` for each, update `bulk_jobs.completed` after each
  - Return job_id immediately
- [ ] Implement `GET /api/bulk/{job_id}` — return job status + all completed results so far

**Bulk Scanner Page (`src/pages/Bulk.jsx`):**
- [ ] `CsvUploader.jsx` — react-dropzone area: dashed border, "Drop CSV file here or click to browse" label, accept `.csv` only, shows filename after selection
- [ ] Template download link: inline CSV string as blob download showing correct format
- [ ] Upload button → `POST /api/bulk/scan` → receives job_id
- [ ] `BulkProgressBar.jsx` — polls `GET /api/bulk/{job_id}` every 2 seconds, shows "17 of 42 scanned" + progress bar
- [ ] `BulkResultsTable.jsx` — appears as results come in, same columns as ReportsTable but without pagination
- [ ] Export button: download all bulk results as CSV when job complete
- [ ] Error handling: invalid file type, empty file, over 500 IoC limit

### Acceptance Criteria
- ML Insights page shows real metrics after Phase 6 training
- Retrain button triggers training and updates metrics after completion
- Feed cards show correct last_synced time for OTX and Abuse.ch
- Refresh button updates a feed card's status in real time
- Uploading a 5-IoC CSV file processes all 5 and shows results table
- Progress bar updates as scans complete (polling working)
- Bulk page shows error for non-CSV file upload

### Done Definition
All 7 pages fully functional. Every route works end-to-end with real data.

---

## Phase 8 — Polish: Skeletons, Error States, README, Final Cleanup

**Goal:** Production-quality feel. Every loading state, every error state, every empty state handled. README lets anyone run the project in 5 minutes. No console errors, no broken states.

### Tasks

**Loading States:**
- [ ] Home page: ScanBar shows spinner in button while scan is in progress, input disabled
- [ ] Results page: `LoadingSkeleton` blocks for each panel while data loads
- [ ] Dashboard: each section has skeleton while its data loads
- [ ] Reports: table rows replaced with skeletons while fetching
- [ ] All loading skeletons use the shimmer animation defined in `index.css`

**Error States:**
- [ ] Results page: `ErrorState` with "Scan not found" if scan_id doesn't exist in DB
- [ ] Results page: `ErrorState` with retry if API call fails
- [ ] Dashboard: each chart section has individual error state (one failing doesn't break others)
- [ ] Reports: `ErrorState` with retry if fetch fails
- [ ] Feed refresh: inline error message on FeedCard if refresh fails
- [ ] ML train: toast notification on success and failure

**Empty States:**
- [ ] Dashboard: `EmptyState` shown if DB has 0 scans ("Run your first scan to see data here")
- [ ] Reports: `EmptyState` if filters return 0 results ("No scans match these filters")
- [ ] Bulk results: `EmptyState` while job is pending (before first result arrives)

**UX Polish:**
- [ ] Sidebar: active route highlighted with cyan accent left border
- [ ] All external links open in new tab
- [ ] Results panels: smooth fade-in on mount (CSS transition)
- [ ] LiveTicker: gracefully hidden if no high/critical threats in DB (no empty marquee)
- [ ] Scan history on Home: show last 3 scans as quick links below ScanBar on revisit
- [ ] `document.title` updated per page: "CTI Aggregator — Dashboard", "CTI Aggregator — Results", etc.

**README.md (final):**
- [ ] Prerequisites: Python 3.11+, Node 20+
- [ ] Step-by-step: clone, backend setup (venv, pip install, .env, uvicorn), frontend setup (npm install, .env, npm run dev)
- [ ] How to get OTX API key (link to otx.alienvault.com, free registration)
- [ ] How to run first scan
- [ ] How to train the ML model (requires 50+ scans first)
- [ ] How to use bulk scan (with sample CSV format)

**Final Cleanup:**
- [ ] Remove all `console.log` debug statements from frontend
- [ ] Remove all `print()` debug statements from backend
- [ ] Verify `.gitignore` covers: `.env`, `*.db`, `*.pkl`, `__pycache__`, `node_modules`, `dist`
- [ ] Verify `backend/.env` is NOT committed
- [ ] Run `npm run build` — confirm no build errors
- [ ] Confirm all 7 routes render without errors on fresh page load (F5 on each)
- [ ] Test full flow: scan → results → dashboard updates → reports shows entry → export CSV

### Acceptance Criteria
- Fresh clone + README steps → both servers running in under 10 minutes
- Every page handles loading, error, and empty states without crashing
- `npm run build` completes with no errors
- No `console.log` or `print()` in production code
- `.env` not committed to repo

### Done Definition
Project is presentable, stable, and documented. All 8 proposal phases covered. Ready for FYP demo.
