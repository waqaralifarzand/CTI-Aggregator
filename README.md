# CTI Aggregator

An automated Cyber Threat Intelligence aggregation and analysis platform for investigating Indicators of Compromise (IoCs).

## What It Does

CTI Aggregator allows security analysts to look up IP addresses, domains, and file hashes against multiple open-source threat intelligence feeds — AlienVault OTX, Abuse.ch URLhaus, and Abuse.ch MalwareBazaar. Results are aggregated and scored in real time, enriched with geolocation and WHOIS data, and classified by a trained Random Forest ML model. The platform also supports bulk IoC scanning via CSV upload, exportable scan history, and a live threat ticker for high-severity findings.

## Tech Stack

| Frontend | Backend |
|---|---|
| React 19 + Vite 5 | FastAPI (Python 3.11+) |
| Tailwind CSS v4 | SQLAlchemy 2.x + SQLite |
| Recharts 2 | scikit-learn (Random Forest) |
| Axios + React Router v6 | httpx, pandas, python-whois |

## Prerequisites

- **Python 3.11+**
- **Node.js 20+**
- **OTX API Key** — free registration at https://otx.alienvault.com (create account → API Integration)
- **VirusTotal API Key** — free registration at https://www.virustotal.com (optional, used for feed health check)

## Setup

### 1. Clone the repo

```bash
git clone https://github.com/waqaralifarzand/CTI-Aggregator
cd CTI-Aggregator
```

### 2. Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and add your API keys:

```env
DATABASE_URL=sqlite:///./cti_aggregator.db
OTX_API_KEY=your_otx_api_key_here
VT_API_KEY=your_virustotal_api_key_here
CORS_ORIGINS=http://localhost:5173
```

Start the backend:

```bash
uvicorn main:app --reload --port 8000
```

### 3. Frontend

```bash
cd frontend
npm install
```

Create `frontend/.env`:

```env
VITE_API_BASE_URL=http://localhost:8000
```

Start the frontend:

```bash
npm run dev
```

### 4. Open the app

Navigate to **http://localhost:5173**

API documentation is available at **http://localhost:8000/docs**

## First Use

1. Go to the **Scanner** (home page) and enter any IP address, domain, or file hash
2. View aggregated results from all threat intelligence feeds
3. Click **Dashboard** to see statistics and charts build up as you run more scans
4. Go to **Scan History** to filter, search, and export your scan history as CSV

## Training the ML Model

The ML classifier requires at least 50 scans before it can be trained.

1. Run 50+ scans from the Scanner page (or use Bulk Scanner with a CSV file)
2. Navigate to **ML Insights** and click **Retrain Model**
3. Training runs in the background (~5–10 seconds) — refresh the page after ~30 seconds to see metrics

## Bulk Scanning

1. Go to **Bulk Scanner**
2. Prepare a CSV file with one IoC per line:

```
8.8.8.8
malware.example.com
44d88612fea8a8f36de82e1278abb02f
```

3. Upload the file — the scanner processes all IoCs and shows live progress
4. Click any result row to view the full scan detail

Maximum 500 IoCs per batch.

## Project Structure

```
CTI-Aggregator/
├── backend/          FastAPI app — routers, models, services, ML pipeline
│   ├── models/       SQLAlchemy ORM models
│   ├── routers/      API endpoints (scan, dashboard, feeds, reports, ml, bulk)
│   ├── services/     OTX, Abuse.ch, geo, WHOIS, ML inference
│   └── ml/           Feature extraction, trainer, model artifacts
└── frontend/         React app — pages, components, hooks
    └── src/
        ├── pages/    7 route pages
        ├── components/  Shared + feature components
        └── hooks/    Data-fetching hooks
```

## Academic Context

Final Year Project (FYP) — Department of Forensic Sciences & Criminology (DFRSC), Lahore Garrison University.
Student: Kaif Naqvi.
