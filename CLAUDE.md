# CLAUDE.md - CTI Aggregator Project Conventions

## Project Overview
Automated Cyber Threat Intelligence Aggregator and Normalization Framework.
Pulls from 4 open-source CTI feeds, normalizes into unified schema, applies
rule-based anomaly detection, and classifies threat severity via Random Forest ML.

**Developer**: Kaif Naqvi
**University**: Lahore Garrison University — BS Digital Forensics & Cybersecurity FYP

## Quick Start
```bash
# Backend
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
cp .env.example .env       # Edit with your API keys
uvicorn backend.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev                 # Runs on http://localhost:5173
```

## Key Commands
```bash
# Run backend
uvicorn backend.main:app --reload --port 8000

# Run all tests
pytest

# Run tests with coverage
pytest --cov=backend --cov-report=html

# Run specific test file
pytest tests/unit/test_connectors/test_urlhaus.py -v

# Train ML model
python scripts/train_model.py --version v1

# Seed database with sample data
python scripts/seed_db.py

# Database migration
python scripts/migrate.py create
python scripts/migrate.py reset    # DESTRUCTIVE

# Frontend dev server
cd frontend && npm run dev
```

## Architecture
```
HTTP Request -> Router -> Service -> Connector/DB/ML
                  |           |
              Pydantic    SQLAlchemy
              Schemas      Models
```

- **Routers** (`backend/routers/`): HTTP layer only. Validation via Pydantic. Delegates to services.
- **Services** (`backend/services/`): Business logic. Orchestrates connectors, DB, and ML.
- **Connectors** (`backend/connectors/`): External API clients. Each extends BaseConnector.
- **Models** (`backend/models/`): SQLAlchemy ORM models. One file per table.
- **Schemas** (`backend/schemas/`): Pydantic request/response models. One file per domain.
- **ML** (`backend/ml/`): Feature extraction, training, prediction. Models saved as .joblib.

## File Index
| Path | Purpose |
|------|---------|
| `backend/main.py` | FastAPI app factory, lifespan, router registration |
| `backend/config.py` | Pydantic BaseSettings (reads .env) |
| `backend/database.py` | SQLAlchemy engine, session factory, Base |
| `backend/models/indicator.py` | Core Indicator ORM model |
| `backend/models/feed_run.py` | Feed fetch history ORM model |
| `backend/models/anomaly_flag.py` | Anomaly detection results ORM model |
| `backend/models/ml_prediction.py` | ML prediction results ORM model |
| `backend/models/scan_history.py` | Audit log ORM model |
| `backend/connectors/base.py` | Abstract BaseConnector with fetch/parse/normalize |
| `backend/connectors/urlhaus.py` | Abuse.ch URLhaus connector |
| `backend/connectors/malwarebazaar.py` | MalwareBazaar connector |
| `backend/connectors/alienvault_otx.py` | AlienVault OTX connector |
| `backend/connectors/misp.py` | MISP instance connector |
| `backend/services/normalization.py` | Normalize raw feed data to unified schema |
| `backend/services/ingestion.py` | Orchestrate fetch->normalize->store pipeline |
| `backend/services/detection.py` | Rule-based anomaly detection engine (5 rules) |
| `backend/ml/features.py` | Feature extraction (30 features) |
| `backend/ml/training.py` | RF training, evaluation, persistence |
| `backend/ml/predict.py` | Predictor class for serving |
| `backend/routers/feeds.py` | /api/v1/feeds/* endpoints |
| `backend/routers/indicators.py` | /api/v1/indicators/* endpoints |
| `backend/routers/anomalies.py` | /api/v1/anomalies/* endpoints |
| `backend/routers/predictions.py` | /api/v1/predictions/* endpoints |
| `backend/routers/dashboard.py` | /api/v1/dashboard/* endpoints |

## Conventions
- **Python**: 3.9+ compatible. Type hints everywhere. Async where I/O-bound.
- **Imports**: stdlib -> third-party -> local. Absolute imports (`from backend.x import y`).
- **Naming**: snake_case for files/functions/variables. PascalCase for classes.
- **DB**: SQLite for dev. PostgreSQL-ready (swap DATABASE_URL in .env).
- **API**: REST. JSON. Prefix `/api/v1/`. Consistent error format: `{"detail": "..."}`.
- **Tests**: pytest. Fixtures in conftest.py. Mock external APIs. No real network calls in tests.
- **Git**: Conventional commits: `feat:`, `fix:`, `test:`, `docs:`, `refactor:`.
- **Secrets**: Never commit .env. Use .env.example as template.

## Environment Variables (.env)
```
DATABASE_URL=sqlite:///./cti_aggregator.db
OTX_API_KEY=your_otx_api_key_here
MISP_URL=https://your-misp-instance.org
MISP_API_KEY=your_misp_api_key_here
MISP_VERIFY_SSL=true
CORS_ORIGINS=["http://localhost:5173"]
LOG_LEVEL=INFO
MODEL_PATH=backend/ml/models/rf_severity_model.joblib
```

## Feed Connector Pattern
Every connector extends `BaseConnector` and implements:
1. `fetch(**kwargs)` - async HTTP call to feed API
2. `parse(raw)` - extract relevant fields from raw response
3. `normalize(parsed)` - map to unified schema dict
4. `run(**kwargs)` - full pipeline (inherited from base)

## Unified IoC Schema Fields
ioc_value, ioc_type, source_feed, source_reference, first_seen, last_seen,
severity, confidence, tags, malware_family, tlp, raw_data

## Detection Rules
1. **duplicate_cross_feed** - Same IoC from multiple feeds
2. **frequency_spike** - Report count > 3x historical median
3. **temporal_correlation** - 3+ IoCs with same malware family in 2-hour window
4. **cross_feed_conflict** - >20% of feeds assign low severity
5. **stale_recency_decay** - Not seen in 180+ days / reactivation detection

## ML Features (30 total)
- Cross-feed: num_sources, feed_agreement, mean/max/min_feed_score
- Temporal: age_days, last_seen_recency, active_duration, reporting_frequency
- Indicator: ioc_type one-hot (6), num_tags, has_malware_family, tlp_numeric
- Detection: anomaly_score, 6 boolean flag features
- Other: has_payload, is_active_ratio, blacklist_count, hour_of_day
