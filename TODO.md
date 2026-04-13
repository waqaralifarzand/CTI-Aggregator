# CTI Aggregator - Project TODO

## Phase 1: Project Setup & Foundation
- [x] Create complete directory structure with all folders and __init__.py files
- [x] Write pyproject.toml with project metadata and tool configs
- [x] Write requirements.txt and requirements-dev.txt
- [x] Create .env.example with all required environment variables
- [x] Create .gitignore (Python, Node, IDE, .env, __pycache__, *.db, *.joblib)
- [x] Implement backend/config.py (Pydantic BaseSettings)
- [x] Implement backend/database.py (SQLAlchemy engine, session, Base)
- [x] Implement all 5 ORM models (indicator, feed_run, anomaly_flag, ml_prediction, scan_history)
- [x] Implement backend/main.py with app factory, lifespan, CORS, router registration
- **Success**: Server starts, /docs shows Swagger UI

## Phase 2: Feed Connectors
- [x] Implement backend/connectors/base.py (abstract BaseConnector)
- [x] Implement backend/utils/rate_limiter.py (token-bucket)
- [x] Implement backend/utils/retry.py (exponential backoff)
- [x] Implement backend/connectors/urlhaus.py (fetch, parse, normalize)
- [x] Implement backend/connectors/malwarebazaar.py
- [x] Implement backend/connectors/alienvault_otx.py
- [x] Implement backend/connectors/misp.py
- [x] Save test fixtures for all 4 feeds
- [x] Write unit tests for all 4 connectors
- **Success**: Each connector.run() returns list of unified-schema dicts; all tests pass

## Phase 3: Normalization & Ingestion
- [x] Implement backend/services/normalization.py
- [x] Implement backend/services/ingestion.py (orchestrate fetch->normalize->store)
- [x] Implement deduplication logic (upsert on ioc_value+source_feed)
- [x] Implement backend/schemas/indicator.py (Pydantic models)
- [x] Implement backend/schemas/feed.py (Pydantic models)
- [x] Write tests for normalization service
- **Success**: ingest_feed() writes to DB; duplicates are merged; tests pass

## Phase 4: API Endpoints
- [x] Implement backend/routers/feeds.py (POST /fetch, GET /status, GET /history)
- [x] Implement backend/routers/indicators.py (GET list, GET detail, GET search, GET export)
- [x] Implement backend/routers/dashboard.py (summary, timeline, top-iocs, feed-health)
- [x] Implement all Pydantic schemas (dashboard, anomaly, prediction)
- [x] Write integration tests for API endpoints
- **Success**: All endpoints return correct data with proper status codes; tests pass

## Phase 5: Detection Engine
- [x] Implement backend/services/detection.py with DetectionEngine class
- [x] Implement rule: duplicate IoC detection (cross-feed)
- [x] Implement rule: frequency spike detection
- [x] Implement rule: temporal correlation detection
- [x] Implement rule: cross-feed conflict detection
- [x] Implement rule: recency decay and reactivation flagging
- [x] Implement backend/routers/anomalies.py
- [x] Write tests for detection rules
- **Success**: Each rule flags correct patterns; engine runs on 1000+ IoCs; tests pass

## Phase 6: ML Pipeline
- [x] Implement backend/ml/features.py (30-feature extraction)
- [x] Implement backend/ml/training.py (bootstrap labels, train RF, evaluate, persist)
- [x] Implement backend/ml/predict.py (Predictor class, single + batch)
- [x] Implement backend/routers/predictions.py
- [x] Write scripts/train_model.py (CLI training trigger)
- [x] Write tests for ML pipeline
- **Success**: Model trains; prediction endpoint returns severity; model persists

## Phase 7: Frontend
- [x] Initialize React+Vite project in frontend/
- [x] Configure Tailwind CSS with dark theme
- [x] Build dark theme layout (Layout.jsx, Sidebar.jsx)
- [x] Build Dashboard page (StatsCard, SeverityChart, TimelineChart, FeedStatusPanel)
- [x] Build Indicators page (ThreatTable with filters, pagination, search)
- [x] Build Anomalies page (flag list with severity badges)
- [x] Build Settings page (feed management, model training)
- [x] Configure Vite proxy to http://localhost:8000
- [x] Build frontend/src/api/client.js (axios API helpers)
- **Success**: Dashboard renders with live API data; dark theme; all pages functional

## Phase 8: Polish & Documentation
- [x] Write test fixtures for all 4 feeds
- [x] Write unit tests for connectors, services, ML
- [x] Write integration tests for all API endpoints
- [x] Write scripts/seed_db.py for demo data
- [x] Write scripts/migrate.py for database management
- [x] Write CLAUDE.md with conventions and file index
- [x] Write TODO.md with phased checklist
- [x] Write docs/PLAN.md with full architecture plan
- [ ] Achieve 80%+ test coverage
- [ ] Write comprehensive README.md with setup instructions and screenshots
- [ ] Performance test with 10,000+ indicators
- **Success**: Docs complete; project runs end-to-end from fresh clone
