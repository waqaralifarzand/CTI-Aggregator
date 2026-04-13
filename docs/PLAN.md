# CTI Aggregator - Architecture & Implementation Plan

## Context
Final Year Project for BS Digital Forensics & Cybersecurity at Lahore Garrison University.
Developer: Kaif Naqvi. The system automates cyber threat intelligence collection,
normalization, anomaly detection, and ML-based severity classification.

## System Architecture

```
┌─────────────┐     ┌──────────────────────────────────────────────────┐
│   React +   │     │                  FastAPI Backend                  │
│   Vite UI   │────▶│                                                  │
│  (port 5173)│     │  ┌────────┐  ┌──────────┐  ┌───────────────┐   │
│             │◀────│  │Routers │─▶│ Services │─▶│  Connectors   │   │
└─────────────┘     │  └────────┘  └──────────┘  │ ┌───────────┐ │   │
                    │       │           │         │ │ URLhaus   │ │   │
                    │       ▼           ▼         │ │ MalBazaar │ │   │
                    │  ┌────────┐  ┌──────────┐  │ │ OTX       │ │   │
                    │  │Pydantic│  │SQLAlchemy│  │ │ MISP      │ │   │
                    │  │Schemas │  │ Models   │  │ └───────────┘ │   │
                    │  └────────┘  └──────────┘  └───────────────┘   │
                    │                    │                             │
                    │              ┌─────▼─────┐  ┌──────────────┐   │
                    │              │  SQLite /  │  │  ML Pipeline │   │
                    │              │ PostgreSQL │  │  (scikit-lr) │   │
                    │              └───────────┘  └──────────────┘   │
                    └──────────────────────────────────────────────────┘
```

## Data Flow

```
Feed API  ──fetch()──▶  Raw JSON  ──parse()──▶  Cleaned Dict  ──normalize()──▶  Unified Schema
                                                                                       │
                                                                                       ▼
Browser  ◀──API──  Router  ◀──Service──  DB  ◀──ingestion──  Validated DataFrame
                     │
                     ├── Detection Engine (5 rules) ──▶ Anomaly Flags
                     └── ML Predictor (Random Forest) ──▶ Severity Classification
```

## Unified Indicator Schema

| Field | Type | Description |
|-------|------|-------------|
| id | int | Auto-increment PK |
| ioc_value | str(2048) | The indicator value (IP, hash, URL, etc.) |
| ioc_type | str(32) | ip, domain, url, hash_md5, hash_sha1, hash_sha256, email, cve |
| source_feed | str(64) | urlhaus, malwarebazaar, alienvault_otx, misp |
| source_reference | str(2048) | URL to indicator on source platform |
| first_seen | datetime | First reported (UTC) |
| last_seen | datetime | Most recent sighting (UTC) |
| severity | str(16) | low, medium, high, critical |
| confidence | float | 0.0 - 100.0 |
| tags | text | JSON-serialized list |
| malware_family | str(256) | E.g., "Emotet", "Mirai" |
| tlp | str(16) | white, green, amber, red |
| raw_data | text | Original JSON from source |
| feed_run_id | int FK | Reference to the ingestion run |
| created_at | datetime | Record creation |
| updated_at | datetime | Last update |

## Feed Connector Design

Each connector extends `BaseConnector` (abstract) and implements:

### URLhaus (No auth)
- POST `https://urlhaus-api.abuse.ch/v1/urls/recent/`
- Returns: URL indicators + payload hashes
- Severity: online=high, offline=medium
- Confidence: 50 + 25*(spamhaus_listed) + 25*(surbl_listed)

### MalwareBazaar (No auth)
- POST `https://mb-api.abuse.ch/api/v1/` with query=get_recent
- Returns: SHA256/MD5/SHA1 hash indicators
- Severity: high default, critical for email_attachment/APT
- Confidence: 90 (confirmed malware)

### AlienVault OTX (Free API key)
- GET `https://otx.alienvault.com/api/v1/pulses/subscribed`
- Returns: Pulses with indicators (IP, domain, URL, hash, email, CVE)
- Severity: is_active + malware_families -> high/medium/low
- Confidence: 60 + 20*(active) + 10*(has_malware)

### MISP (API key + instance URL)
- POST `{MISP_URL}/events/restSearch`
- Returns: Events with Attributes
- Severity: threat_level_id (1=critical, 2=high, 3=medium, 4=low)
- Confidence: 40 + 30*(to_ids) + analysis*15

## Detection Rules

1. **Duplicate Cross-Feed**: IoC in >1 feed → score +20*num_sources
2. **Frequency Spike**: Today's count > 3x 90-day median → score +30
3. **Temporal Correlation**: 3+ IoCs same malware family in 2h window → score +25
4. **Cross-Feed Conflict**: >20% feeds say "low" → score -15, flagged unreliable
5. **Recency Decay**: Not seen 180+ days → score -20; reactivation → score +40

## ML Pipeline

### Features (30 total)
- Cross-feed: num_sources, mean/max/min_feed_score, feed_agreement, num_malware_families
- Temporal: age_days, last_seen_recency_days, active_duration_days, reporting_frequency, hour_of_day
- Indicator: 6 ioc_type one-hot, num_tags, has_malware_family, tlp_numeric, has_payload, is_active_ratio
- Detection: anomaly_score + 6 boolean flags
- Other: blacklist_count

### Training
- Bootstrap labels from rule-based severity (cold start)
- Random Forest: n_estimators=200, max_depth=15, class_weight=balanced
- 80/20 stratified split, 5-fold cross-validation
- Persist with joblib, versioned files

### Target: F1 > 0.70 on bootstrapped data

## API Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| /api/v1/feeds/fetch | POST | Trigger feed fetch |
| /api/v1/feeds/status | GET | All feed statuses |
| /api/v1/feeds/history | GET | Feed run history |
| /api/v1/indicators | GET | List with filters/pagination |
| /api/v1/indicators/search | GET | Search by IoC value |
| /api/v1/indicators/export | GET | CSV export |
| /api/v1/indicators/{id} | GET | Single indicator detail |
| /api/v1/anomalies | GET | List anomaly flags |
| /api/v1/anomalies/run | POST | Trigger detection engine |
| /api/v1/anomalies/summary | GET | Anomaly statistics |
| /api/v1/predictions/classify | POST | Classify single IoC |
| /api/v1/predictions/batch | POST | Batch classification |
| /api/v1/predictions/train | POST | Trigger model training |
| /api/v1/predictions/model-info | GET | Model metadata |
| /api/v1/dashboard/summary | GET | Overview statistics |
| /api/v1/dashboard/timeline | GET | IoCs over time |
| /api/v1/dashboard/top-iocs | GET | Most reported IoCs |
| /api/v1/dashboard/feed-health | GET | Feed health metrics |
| /api/v1/dashboard/recent-activity | GET | Activity log |

## Database Tables

- **indicators**: Core IoC storage (16 columns, 3 indexes)
- **feed_runs**: Fetch history per feed (10 columns)
- **anomaly_flags**: Detection results linked to indicators (7 columns)
- **ml_predictions**: ML classification results (7 columns)
- **scan_history**: Audit log for all system actions (5 columns)

## Build Order

1. **Phase 1** (Foundation): Directory structure, config, database, ORM models, app factory
2. **Phase 2** (Connectors): Base class → URLhaus → MalwareBazaar → OTX → MISP
3. **Phase 3** (Pipeline): Normalization service, ingestion orchestration, deduplication
4. **Phase 4** (API): All 5 routers with Pydantic schemas
5. **Phase 5** (Detection): 5 anomaly detection rules, flag persistence
6. **Phase 6** (ML): Feature extraction, Random Forest training, prediction serving
7. **Phase 7** (Frontend): React+Vite, dark theme, Dashboard/Indicators/Anomalies/Settings
8. **Phase 8** (Polish): Tests, documentation, seed data, coverage

## Verification

```bash
# 1. Install and start backend
pip install -r requirements.txt && uvicorn backend.main:app --reload

# 2. Seed sample data
python scripts/seed_db.py

# 3. Run tests
pytest -v

# 4. Fetch from live feeds (URLhaus, no auth needed)
curl -X POST http://localhost:8000/api/v1/feeds/fetch -H 'Content-Type: application/json' -d '{"feed":"urlhaus"}'

# 5. Check indicators
curl http://localhost:8000/api/v1/indicators

# 6. Run detection
curl -X POST http://localhost:8000/api/v1/anomalies/run

# 7. Train ML model
python scripts/train_model.py --version v1

# 8. Start frontend
cd frontend && npm install && npm run dev
```
