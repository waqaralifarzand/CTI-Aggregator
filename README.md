# CTI Aggregator

**Automated Cyber Threat Intelligence Aggregator and Normalization Framework**

A Python + React application that pulls threat data from multiple open-source CTI feeds, normalizes it into a unified schema, applies rule-based anomaly detection, and classifies threat severity using Random Forest ML.

**Developer**: Kaif Naqvi
**University**: Lahore Garrison University — BS Digital Forensics & Cybersecurity FYP

## Features

- **Multi-Feed Ingestion**: Pulls from AlienVault OTX, Abuse.ch URLhaus, MalwareBazaar, and MISP
- **Unified Schema**: Normalizes JSON, CSV, and STIX/TAXII formats into a single indicator model
- **Anomaly Detection**: 5 rule-based detection rules (duplicate detection, frequency spikes, temporal correlation, cross-feed conflicts, recency decay)
- **ML Classification**: Random Forest severity classifier with 30 engineered features
- **REST API**: FastAPI backend with full CRUD, filtering, pagination, and CSV export
- **Dark Dashboard**: React + Tailwind CSS frontend with charts, tables, and feed management

## Architecture

```
HTTP Request -> Router -> Service -> Connector/DB/ML
                  |           |
              Pydantic    SQLAlchemy
              Schemas      Models
```

## Quick Start

### Backend

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
cp .env.example .env            # Edit with your API keys
uvicorn backend.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev                     # Runs on http://localhost:5173
```

### Seed Sample Data

```bash
python scripts/seed_db.py
```

### Run Tests

```bash
pytest -v
pytest --cov=backend --cov-report=html
```

## API Endpoints

| Route | Method | Description |
|-------|--------|-------------|
| `/api/v1/feeds/fetch` | POST | Trigger feed fetch |
| `/api/v1/feeds/status` | GET | All feed statuses |
| `/api/v1/indicators` | GET | List with filters/pagination |
| `/api/v1/indicators/search` | GET | Search by IoC value |
| `/api/v1/indicators/export` | GET | CSV export |
| `/api/v1/anomalies/run` | POST | Trigger detection engine |
| `/api/v1/anomalies` | GET | List anomaly flags |
| `/api/v1/predictions/classify` | POST | ML severity classification |
| `/api/v1/predictions/train` | POST | Train/retrain ML model |
| `/api/v1/dashboard/summary` | GET | Dashboard statistics |
| `/api/v1/dashboard/timeline` | GET | IoCs over time |

Full Swagger UI available at `http://localhost:8000/docs`

## CTI Feeds

| Feed | Auth | IoC Types |
|------|------|-----------|
| URLhaus | None (public) | URLs, file hashes |
| MalwareBazaar | None (public) | SHA256, MD5, SHA1 hashes |
| AlienVault OTX | Free API key | IPs, domains, URLs, hashes, emails, CVEs |
| MISP | API key + instance URL | IPs, domains, URLs, hashes, emails |

## Tech Stack

- **Backend**: Python 3.9+, FastAPI, SQLAlchemy, pandas, scikit-learn
- **Frontend**: React 18, Vite, Tailwind CSS, Recharts, Axios
- **Database**: SQLite (dev) / PostgreSQL (production-ready)
- **ML**: Random Forest classifier with joblib persistence

## Project Structure

```
CTI-Aggregator/
├── backend/
│   ├── connectors/     # Feed API clients (4 connectors)
│   ├── models/         # SQLAlchemy ORM models (5 tables)
│   ├── schemas/        # Pydantic request/response models
│   ├── services/       # Business logic (normalization, ingestion, detection)
│   ├── routers/        # FastAPI route handlers (5 routers)
│   ├── ml/             # ML pipeline (features, training, prediction)
│   └── utils/          # Rate limiter, retry, logging
├── frontend/src/
│   ├── components/     # Reusable UI components
│   ├── pages/          # Dashboard, Indicators, Anomalies, Settings
│   ├── api/            # Axios API client
│   └── hooks/          # Custom React hooks
├── tests/              # Unit + integration tests with fixtures
├── scripts/            # DB seeding, model training, migration
└── docs/               # Architecture and API documentation
```

## License

This project is developed as a Final Year Project for academic purposes.
