# ARCHITECTURE.md — CTI Aggregator Technical Structure

> Source of truth for folder structure, API contracts, DB schema, and component map.
> Claude Code reads this before writing any file.

---

## Tech Stack Version Table

| Technology | Version | Purpose |
|---|---|---|
| Python | 3.11+ | Backend runtime |
| FastAPI | 0.111+ | API framework |
| SQLAlchemy | 2.x | ORM |
| Pydantic | 2.x | Request/response validation |
| httpx | 0.27+ | Async HTTP client for feed APIs |
| scikit-learn | 1.5+ | Random Forest ML classifier |
| pandas | 2.x | Data normalization |
| python-whois | 0.9+ | WHOIS domain lookups |
| joblib | 1.4+ | Model serialization (.pkl) |
| python-multipart | 0.0.9+ | CSV file upload parsing |
| python-dotenv | 1.0+ | .env loading |
| uvicorn | 0.29+ | ASGI server |
| Node.js | 20+ | Frontend runtime |
| React | 18 | UI framework |
| Vite | 5 | Build tool |
| Tailwind CSS | 3 | Utility styling |
| Recharts | 2 | Charts (donut, bar, line) |
| Axios | 1.x | HTTP client |
| React Router | 6 | Client-side routing |
| react-dropzone | 14+ | CSV drag-and-drop upload |

---

## Complete Folder Structure

```
CTI-Aggregator/
│
├── CLAUDE.md                          # Project identity — read first every session
├── ARCHITECTURE.md                    # This file
├── PHASES.md                          # Execution roadmap
├── SCRATCHPAD.md                      # Session memory — updated after every phase
├── README.md                          # Basic run instructions
├── .gitignore
│
├── backend/
│   ├── .env                           # DATABASE_URL, OTX_API_KEY, CORS_ORIGINS
│   ├── .env.example                   # Template with placeholder values
│   ├── requirements.txt               # All Python dependencies
│   ├── main.py                        # FastAPI app init, CORS, router registration
│   ├── database.py                    # SQLAlchemy engine, SessionLocal, Base, get_db
│   │
│   ├── models/                        # SQLAlchemy ORM models (DB tables)
│   │   ├── __init__.py
│   │   ├── ioc.py                     # IoC table
│   │   ├── scan_result.py             # ScanResult table
│   │   ├── feed_result.py             # Per-feed result rows
│   │   └── feed_status.py             # Feed health tracking
│   │
│   ├── schemas/                       # Pydantic request/response shapes
│   │   ├── __init__.py
│   │   ├── scan.py                    # ScanRequest, ScanResponse, ScanSummary
│   │   ├── feed.py                    # FeedStatusResponse, FeedRefreshResponse
│   │   ├── reports.py                 # ReportRow, ReportFilter, ExportResponse
│   │   ├── ml.py                      # MLMetrics, FeatureImportance, TrainResponse
│   │   └── dashboard.py               # DashboardStats, ActivityPoint, TickerItem
│   │
│   ├── routers/                       # FastAPI route handlers
│   │   ├── __init__.py
│   │   ├── scan.py                    # POST /api/scan, GET /api/scan/{scan_id}
│   │   ├── bulk.py                    # POST /api/bulk/scan, GET /api/bulk/{job_id}
│   │   ├── feeds.py                   # GET /api/feeds, POST /api/feeds/{name}/refresh
│   │   ├── reports.py                 # GET /api/reports, GET /api/reports/export
│   │   ├── ml.py                      # GET /api/ml/metrics, POST /api/ml/train
│   │   └── dashboard.py               # GET /api/dashboard/stats, /activity, /ticker
│   │
│   ├── services/                      # Business logic — pure functions, no DB writes
│   │   ├── __init__.py
│   │   ├── ioc_detector.py            # Auto-detect IoC type from raw string
│   │   ├── otx_service.py             # AlienVault OTX API calls
│   │   ├── abusech_service.py         # URLhaus + MalwareBazaar API calls
│   │   ├── geo_service.py             # ip-api.com geolocation (IP only)
│   │   ├── whois_service.py           # python-whois WHOIS lookup (domain only)
│   │   ├── aggregator_service.py      # Orchestrates all services for one IoC scan
│   │   └── ml_service.py              # Train model, predict severity, get metrics
│   │
│   ├── ml/                            # ML artifacts and logic
│   │   ├── __init__.py
│   │   ├── trainer.py                 # Build dataset from DB, train RF, save model
│   │   ├── features.py                # Extract feature vector from scan result dict
│   │   ├── model.pkl                  # Saved trained model (created at runtime)
│   │   └── label_encoder.pkl          # Saved label encoder (created at runtime)
│   │
│   └── utils/
│       ├── __init__.py
│       ├── response.py                # Standard envelope helper: ok() and err()
│       └── severity.py                # Rule-based severity scoring (0–100 → label)
│
└── frontend/
    ├── .env                           # VITE_API_BASE_URL=http://localhost:8000
    ├── .env.example
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js             # Extend with CSS variable references
    ├── index.html                     # Google Fonts import: DM Sans + JetBrains Mono
    └── src/
        ├── main.jsx                   # ReactDOM.createRoot, BrowserRouter
        ├── App.jsx                    # Route definitions (React Router v6)
        ├── index.css                  # CSS variables, base reset, font declarations
        │
        ├── api/
        │   └── client.js              # Axios instance + all typed API call functions
        │
        ├── hooks/
        │   ├── useScan.js             # Scan state: loading, result, error
        │   ├── useDashboard.js        # Dashboard data fetching
        │   └── useReports.js          # Reports with filter state
        │
        ├── pages/
        │   ├── Home.jsx               # Hero scanner page
        │   ├── Results.jsx            # /results/:scanId — shareable scan permalink
        │   ├── Dashboard.jsx          # Stats, charts, ticker
        │   ├── Reports.jsx            # Scan history table
        │   ├── Feeds.jsx              # Feed manager
        │   ├── MLInsights.jsx         # Model metrics + retrain
        │   └── Bulk.jsx               # CSV batch scanner
        │
        └── components/
            ├── layout/
            │   ├── Sidebar.jsx        # Fixed left nav (240px), route links, logo
            │   ├── TopBar.jsx         # Page title + optional action button
            │   └── PageWrapper.jsx    # Consistent padding/max-width wrapper
            │
            ├── scanner/
            │   ├── ScanBar.jsx        # Hero input: large text input + scan button
            │   ├── IocTypeBadge.jsx   # Pill showing auto-detected type (IP/Domain/Hash)
            │   └── ScanningState.jsx  # Animated loading state during scan
            │
            ├── results/
            │   ├── ThreatOverviewCard.jsx    # Top card: severity, score, IoC value, share
            │   ├── OTXPanel.jsx              # OTX pulse count, tags, categories
            │   ├── AbuseChPanel.jsx          # URLhaus + MalwareBazaar hits
            │   ├── BlacklistPanel.jsx        # Blacklist status grid (found/not found)
            │   ├── MLPredictionPanel.jsx     # RF prediction + confidence bar
            │   ├── GeoPanel.jsx              # Country, ASN, ISP (IP only)
            │   ├── WhoisPanel.jsx            # Registrar, creation date (domain only)
            │   └── RecommendationsPanel.jsx  # 2–3 analyst action bullets
            │
            ├── dashboard/
            │   ├── StatCard.jsx              # Single metric: label + value + icon
            │   ├── SeverityDonut.jsx         # Recharts donut: threats by severity
            │   ├── IocTypeBar.jsx            # Recharts bar: scans by IoC type
            │   ├── ActivityLine.jsx          # Recharts line: 7-day scan volume
            │   ├── RecentScansTable.jsx      # Last 10 scans with severity + link
            │   ├── FeedHealthWidget.jsx      # OTX / Abuse.ch status pills
            │   └── LiveTicker.jsx            # Scrolling latest threats banner
            │
            ├── reports/
            │   ├── ReportsTable.jsx          # Full paginated scan history
            │   ├── FilterBar.jsx             # Severity / type / date range filters
            │   └── ExportButton.jsx          # Triggers CSV download
            │
            ├── feeds/
            │   └── FeedCard.jsx              # Feed name, status, last synced, refresh btn
            │
            ├── ml/
            │   ├── MetricCard.jsx            # Single metric: Accuracy / Precision / etc.
            │   ├── FeatureImportanceChart.jsx # Recharts bar: feature weights
            │   └── RetrainButton.jsx         # Triggers POST /api/ml/train
            │
            ├── bulk/
            │   ├── CsvUploader.jsx           # react-dropzone CSV upload area
            │   ├── BulkProgressBar.jsx       # Progress: N of M scanned
            │   └── BulkResultsTable.jsx      # Results table for batch job
            │
            └── shared/
                ├── SeverityBadge.jsx         # Pill: Critical / High / Medium / Low / Clean
                ├── CopyButton.jsx            # Copy IoC value to clipboard
                ├── ShareButton.jsx           # Copy shareable result URL
                ├── LoadingSkeleton.jsx       # Animated gray placeholder blocks
                ├── EmptyState.jsx            # "No data yet" illustration + message
                └── ErrorState.jsx            # API error display with retry option
```

---

## Database Schema

### Table: `iocs`
Stores every unique IoC value ever submitted.

```sql
CREATE TABLE iocs (
    id          INTEGER     PRIMARY KEY AUTOINCREMENT,
    value       TEXT        NOT NULL UNIQUE,
    type        TEXT        NOT NULL,       -- 'ip' | 'domain' | 'hash_md5' | 'hash_sha256'
    first_seen  TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen   TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scan_count  INTEGER     NOT NULL DEFAULT 1
);
```

### Table: `scan_results`
One row per scan submission. The `scan_id` is the UUID used in shareable URLs.

```sql
CREATE TABLE scan_results (
    id               INTEGER     PRIMARY KEY AUTOINCREMENT,
    scan_id          TEXT        NOT NULL UNIQUE,   -- UUID v4
    ioc_id           INTEGER     NOT NULL REFERENCES iocs(id),
    overall_severity TEXT        NOT NULL,          -- 'critical'|'high'|'medium'|'low'|'clean'
    ml_severity      TEXT,                          -- RF prediction (nullable until model trained)
    ml_confidence    REAL,                          -- 0.0 – 1.0
    threat_score     INTEGER     NOT NULL DEFAULT 0, -- 0–100 computed rule-based score
    scanned_at       TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    raw_summary      TEXT        NOT NULL            -- JSON blob of aggregated results
);
```

### Table: `feed_results`
One row per feed per scan. Allows per-feed breakdown in the result panels.

```sql
CREATE TABLE feed_results (
    id              INTEGER     PRIMARY KEY AUTOINCREMENT,
    scan_result_id  INTEGER     NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    feed_name       TEXT        NOT NULL,   -- 'otx'|'urlhaus'|'malwarebazaar'|'geo'|'whois'
    found           BOOLEAN     NOT NULL DEFAULT FALSE,
    threat_tags     TEXT,                   -- comma-separated tags from feed
    raw_data        TEXT        NOT NULL,   -- full JSON response from feed
    created_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Table: `feed_status`
One row per feed. Tracks health for the Feed Manager page.

```sql
CREATE TABLE feed_status (
    id             INTEGER     PRIMARY KEY AUTOINCREMENT,
    feed_name      TEXT        NOT NULL UNIQUE,
    status         TEXT        NOT NULL DEFAULT 'unknown', -- 'active'|'error'|'syncing'
    last_synced    TIMESTAMP,
    record_count   INTEGER     NOT NULL DEFAULT 0,
    error_message  TEXT,
    updated_at     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);
```

### Table: `bulk_jobs`
Tracks CSV batch scan jobs.

```sql
CREATE TABLE bulk_jobs (
    id            INTEGER     PRIMARY KEY AUTOINCREMENT,
    job_id        TEXT        NOT NULL UNIQUE,   -- UUID v4
    total         INTEGER     NOT NULL DEFAULT 0,
    completed     INTEGER     NOT NULL DEFAULT 0,
    failed        INTEGER     NOT NULL DEFAULT 0,
    status        TEXT        NOT NULL DEFAULT 'pending', -- 'pending'|'running'|'done'|'error'
    created_at    TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at   TIMESTAMP
);
```

---

## API Endpoints

All responses use the standard envelope:
```json
{ "success": true, "data": {}, "error": null }
{ "success": false, "data": null, "error": "message" }
```

---

### Scan

#### `POST /api/scan`
Submit a single IoC for scanning against all feeds.

**Request body:**
```json
{ "value": "8.8.8.8" }
```

**Response `data`:**
```json
{
  "scan_id": "uuid-v4",
  "ioc": { "value": "8.8.8.8", "type": "ip" },
  "overall_severity": "low",
  "threat_score": 12,
  "ml_severity": "low",
  "ml_confidence": 0.87,
  "scanned_at": "2024-01-15T10:30:00Z",
  "feeds": {
    "otx": {
      "found": true,
      "pulse_count": 2,
      "threat_tags": ["scanner", "bruteforce"],
      "categories": ["Scanning Host"],
      "country": "US",
      "raw_data": {}
    },
    "urlhaus": { "found": false, "raw_data": {} },
    "malwarebazaar": { "found": false, "raw_data": {} },
    "geo": {
      "country": "United States",
      "country_code": "US",
      "region": "California",
      "city": "Mountain View",
      "isp": "Google LLC",
      "asn": "AS15169"
    },
    "whois": null
  },
  "blacklist_status": {
    "google_safebrowsing": "clean",
    "otx_blacklist": "flagged"
  },
  "recommendations": [
    "Monitor outbound connections to this IP — flagged in OTX as scanning host.",
    "Low threat score. No immediate action required.",
    "Consider blocking at perimeter if IP appears in internal logs."
  ]
}
```

---

#### `GET /api/scan/{scan_id}`
Retrieve a scan by its UUID. Used by the shareable `/results/:scanId` route.

**Response `data`:** Same shape as `POST /api/scan` response.

---

#### `GET /api/scans/recent?limit=10`
Get the N most recent scans for the dashboard table.

**Response `data`:**
```json
[
  {
    "scan_id": "uuid",
    "ioc_value": "8.8.8.8",
    "ioc_type": "ip",
    "overall_severity": "low",
    "threat_score": 12,
    "scanned_at": "2024-01-15T10:30:00Z"
  }
]
```

---

### Bulk Scan

#### `POST /api/bulk/scan`
Upload a CSV file containing one IoC per line. Starts a background job.

**Request:** `multipart/form-data` with field `file` (CSV).

**CSV format:**
```
8.8.8.8
malware.example.com
44d88612fea8a8f36de82e1278abb02f
```

**Response `data`:**
```json
{ "job_id": "uuid-v4", "total": 42, "status": "running" }
```

---

#### `GET /api/bulk/{job_id}`
Poll bulk job status and results.

**Response `data`:**
```json
{
  "job_id": "uuid",
  "status": "running",
  "total": 42,
  "completed": 17,
  "failed": 0,
  "results": [
    {
      "ioc_value": "8.8.8.8",
      "ioc_type": "ip",
      "overall_severity": "low",
      "threat_score": 12,
      "scan_id": "uuid"
    }
  ]
}
```

---

### Feeds

#### `GET /api/feeds`
Get health status of all integrated feeds.

**Response `data`:**
```json
[
  {
    "feed_name": "otx",
    "display_name": "AlienVault OTX",
    "status": "active",
    "last_synced": "2024-01-15T09:00:00Z",
    "record_count": 1240,
    "error_message": null
  },
  {
    "feed_name": "urlhaus",
    "display_name": "Abuse.ch URLhaus",
    "status": "active",
    "last_synced": "2024-01-15T09:05:00Z",
    "record_count": 892,
    "error_message": null
  }
]
```

---

#### `POST /api/feeds/{feed_name}/refresh`
Trigger a manual health check + status update for a specific feed.
`feed_name`: `otx` | `urlhaus` | `malwarebazaar`

**Response `data`:**
```json
{ "feed_name": "otx", "status": "active", "message": "Feed verified successfully." }
```

---

### Reports

#### `GET /api/reports`
Paginated, filterable scan history.

**Query params:**
- `page` (int, default 1)
- `limit` (int, default 20)
- `severity` (str: `critical|high|medium|low|clean`)
- `ioc_type` (str: `ip|domain|hash_md5|hash_sha256`)
- `date_from` (ISO date string)
- `date_to` (ISO date string)
- `search` (str: partial IoC value match)

**Response `data`:**
```json
{
  "total": 247,
  "page": 1,
  "limit": 20,
  "results": [
    {
      "scan_id": "uuid",
      "ioc_value": "8.8.8.8",
      "ioc_type": "ip",
      "overall_severity": "low",
      "threat_score": 12,
      "ml_severity": "low",
      "scanned_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

---

#### `GET /api/reports/export`
Download filtered scan history as a CSV file.
Accepts same query params as `GET /api/reports`.

**Response:** `text/csv` file download.
**Filename:** `cti_report_{timestamp}.csv`

**CSV columns:**
`scan_id, ioc_value, ioc_type, overall_severity, threat_score, ml_severity, ml_confidence, scanned_at`

---

### ML

#### `GET /api/ml/metrics`
Get current model performance metrics.

**Response `data`:**
```json
{
  "model_trained": true,
  "last_trained": "2024-01-14T22:00:00Z",
  "training_samples": 180,
  "accuracy": 0.89,
  "precision": 0.87,
  "recall": 0.91,
  "f1_score": 0.89,
  "feature_importance": [
    { "feature": "otx_pulse_count", "importance": 0.34 },
    { "feature": "urlhaus_found", "importance": 0.28 },
    { "feature": "threat_score", "importance": 0.21 },
    { "feature": "malwarebazaar_found", "importance": 0.17 }
  ]
}
```

---

#### `POST /api/ml/train`
Trigger model retraining from current DB data. Runs as background task.

**Response `data`:**
```json
{ "message": "Model training started.", "training_samples": 180 }
```

---

### Dashboard

#### `GET /api/dashboard/stats`
Summary counts for the four stat cards.

**Response `data`:**
```json
{
  "total_scans": 247,
  "threats_found": 89,
  "critical_alerts": 12,
  "clean_scans": 158
}
```

---

#### `GET /api/dashboard/activity?days=7`
Scan volume per day for the activity line chart.

**Response `data`:**
```json
[
  { "date": "2024-01-09", "scans": 14, "threats": 5 },
  { "date": "2024-01-10", "scans": 22, "threats": 8 }
]
```

---

#### `GET /api/dashboard/ticker?limit=20`
Latest high/critical severity findings for the live ticker banner.

**Response `data`:**
```json
[
  {
    "ioc_value": "192.168.1.1",
    "ioc_type": "ip",
    "severity": "high",
    "tags": ["botnet", "c2"],
    "scanned_at": "2024-01-15T10:28:00Z"
  }
]
```

---

#### `GET /api/dashboard/severity-breakdown`
Threat counts by severity for the donut chart.

**Response `data`:**
```json
[
  { "severity": "critical", "count": 12 },
  { "severity": "high", "count": 31 },
  { "severity": "medium", "count": 46 },
  { "severity": "low", "count": 69 },
  { "severity": "clean", "count": 89 }
]
```

---

#### `GET /api/dashboard/ioc-breakdown`
Scan counts by IoC type for the bar chart.

**Response `data`:**
```json
[
  { "type": "ip", "count": 120 },
  { "type": "domain", "count": 85 },
  { "type": "hash_md5", "count": 28 },
  { "type": "hash_sha256", "count": 14 }
]
```

---

## IoC Auto-Detection Logic

Handled in `backend/services/ioc_detector.py`. Server-side only. Never exposed to frontend.

| Pattern | Detected Type |
|---|---|
| Valid IPv4 (e.g. `8.8.8.8`) | `ip` |
| Valid IPv6 | `ip` |
| MD5 — exactly 32 hex chars | `hash_md5` |
| SHA256 — exactly 64 hex chars | `hash_sha256` |
| SHA1 — exactly 40 hex chars | `hash_sha1` |
| Everything else with a dot and TLD | `domain` |

---

## Severity Scoring Logic

Handled in `backend/utils/severity.py`. Computes a `threat_score` (0–100) from feed results.

| Condition | Points |
|---|---|
| Found in OTX (any pulse) | +20 |
| OTX pulse count > 5 | +15 |
| OTX pulse count > 20 | +25 (instead of +15) |
| Found in URLhaus | +30 |
| Found in MalwareBazaar | +35 |
| Found in both URLhaus + MalwareBazaar | +10 bonus |
| OTX tag contains: c2, botnet, ransomware, rat | +15 |

**Score → Severity label:**

| Score | Severity |
|---|---|
| 0 | `clean` |
| 1–25 | `low` |
| 26–50 | `medium` |
| 51–75 | `high` |
| 76–100 | `critical` |

---

## ML Feature Vector

Defined in `backend/ml/features.py`. Input to Random Forest classifier.

| Feature | Type | Source |
|---|---|---|
| `otx_pulse_count` | int | OTX response |
| `otx_found` | 0/1 | OTX response |
| `urlhaus_found` | 0/1 | URLhaus response |
| `malwarebazaar_found` | 0/1 | MalwareBazaar response |
| `threat_score` | int (0–100) | severity.py |
| `ioc_type_ip` | 0/1 | ioc_detector.py |
| `ioc_type_domain` | 0/1 | ioc_detector.py |
| `ioc_type_hash` | 0/1 | ioc_detector.py |
| `otx_has_c2_tag` | 0/1 | OTX tags |
| `otx_has_malware_tag` | 0/1 | OTX tags |

**Label:** `overall_severity` from `scan_results` table (`clean/low/medium/high/critical`)

**Model:** `RandomForestClassifier(n_estimators=100, random_state=42)`

Minimum training samples required: **50 rows** in `scan_results`. Below this, `/api/ml/train` returns an informative error.

---

## Component Hierarchy (Visual)

```
App.jsx
└── Sidebar.jsx (fixed left, always visible)
│
├── / → Home.jsx
│   ├── ScanBar.jsx
│   │   └── IocTypeBadge.jsx (appears after typing)
│   ├── ScanningState.jsx (while loading)
│   └── [on result] → redirect to /results/:scanId
│
├── /results/:scanId → Results.jsx
│   ├── TopBar.jsx (page title + ShareButton + CopyButton)
│   ├── ThreatOverviewCard.jsx
│   │   └── SeverityBadge.jsx
│   ├── OTXPanel.jsx
│   ├── AbuseChPanel.jsx
│   ├── BlacklistPanel.jsx
│   ├── MLPredictionPanel.jsx
│   ├── GeoPanel.jsx (IP only — conditional render)
│   ├── WhoisPanel.jsx (domain only — conditional render)
│   └── RecommendationsPanel.jsx
│
├── /dashboard → Dashboard.jsx
│   ├── LiveTicker.jsx (top banner)
│   ├── StatCard.jsx × 4
│   ├── SeverityDonut.jsx
│   ├── IocTypeBar.jsx
│   ├── ActivityLine.jsx
│   ├── FeedHealthWidget.jsx × 2
│   └── RecentScansTable.jsx
│
├── /reports → Reports.jsx
│   ├── FilterBar.jsx
│   ├── ExportButton.jsx
│   └── ReportsTable.jsx
│
├── /feeds → Feeds.jsx
│   └── FeedCard.jsx × 3 (OTX, URLhaus, MalwareBazaar)
│
├── /ml → MLInsights.jsx
│   ├── MetricCard.jsx × 4 (Accuracy, Precision, Recall, F1)
│   ├── FeatureImportanceChart.jsx
│   └── RetrainButton.jsx
│
└── /bulk → Bulk.jsx
    ├── CsvUploader.jsx
    ├── BulkProgressBar.jsx (after upload)
    └── BulkResultsTable.jsx (after completion)
```

---

## Data Flow — Single IoC Scan

```
User types IoC → ScanBar.jsx
    │
    ▼ POST /api/scan { value: "..." }
backend/routers/scan.py
    │
    ├── services/ioc_detector.py → detect type
    ├── services/aggregator_service.py
    │   ├── services/otx_service.py       → OTX API call
    │   ├── services/abusech_service.py   → URLhaus + MalwareBazaar
    │   ├── services/geo_service.py       → ip-api.com (if IP)
    │   └── services/whois_service.py     → python-whois (if domain)
    │
    ├── utils/severity.py → compute threat_score + overall_severity
    ├── services/ml_service.py → predict severity (if model trained)
    │
    ├── Write to DB: iocs, scan_results, feed_results
    └── Return ScanResponse
         │
         ▼
frontend redirects → /results/{scan_id}
Results.jsx renders all panels from response data
```

---

## Environment Variables Reference

### `backend/.env`
```
DATABASE_URL=sqlite:///./cti_aggregator.db
OTX_API_KEY=your_otx_api_key_here
CORS_ORIGINS=http://localhost:5173
```

### `frontend/.env`
```
VITE_API_BASE_URL=http://localhost:8000
```

### `backend/.env.example` (committed to repo)
```
DATABASE_URL=sqlite:///./cti_aggregator.db
OTX_API_KEY=REPLACE_WITH_YOUR_OTX_KEY
CORS_ORIGINS=http://localhost:5173
```
