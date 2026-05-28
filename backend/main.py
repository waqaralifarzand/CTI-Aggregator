from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv()

from .database import create_tables
from .models import *  # ensure all models are registered
from .routers import scan, bulk, feeds, reports, ml, dashboard

app = FastAPI(title="CTI Aggregator API", version="1.0.0")

origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    create_tables()
    _seed_feed_status()


def _seed_feed_status():
    from .database import SessionLocal
    from .models.feed_status import FeedStatus
    from datetime import datetime, timezone

    feeds = ["otx", "urlhaus", "malwarebazaar", "virustotal"]
    db = SessionLocal()
    try:
        for feed_name in feeds:
            if not db.query(FeedStatus).filter(FeedStatus.feed_name == feed_name).first():
                db.add(FeedStatus(
                    feed_name=feed_name,
                    status="unknown",
                    updated_at=datetime.now(timezone.utc),
                ))
        db.commit()
    finally:
        db.close()


@app.get("/api/health")
async def health():
    from .utils.response import ok
    return ok({"status": "ok", "db": "connected"})


app.include_router(scan.router, prefix="/api")
app.include_router(bulk.router, prefix="/api")
app.include_router(feeds.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(ml.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
