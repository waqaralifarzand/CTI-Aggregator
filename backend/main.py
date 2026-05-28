import os
from contextlib import asynccontextmanager
from datetime import datetime

from dotenv import load_dotenv

# Load environment variables before any other imports that read them
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import OperationalError

from database import engine, SessionLocal, Base

# Import all models so their tables are registered with Base before create_all
import models.ioc  # noqa: F401
import models.scan_result  # noqa: F401
import models.feed_result  # noqa: F401
import models.feed_status  # noqa: F401
import models.bulk_job  # noqa: F401

from models.feed_status import FeedStatus

# Import routers
from routers import scan as scan_router
from routers import dashboard as dashboard_router
from routers import feeds as feeds_router
from routers import reports as reports_router
from routers import ml as ml_router
from routers import bulk as bulk_router


def _init_db():
    """Create all tables and seed initial feed_status rows."""
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        for feed_name in ("otx", "urlhaus", "malwarebazaar"):
            existing = db.query(FeedStatus).filter(FeedStatus.feed_name == feed_name).first()
            if existing is None:
                db.add(
                    FeedStatus(
                        feed_name=feed_name,
                        status="unknown",
                        last_synced=None,
                        record_count=0,
                        error_message=None,
                        updated_at=datetime.utcnow(),
                    )
                )
        db.commit()
    except Exception as exc:
        db.rollback()
        print(f"[startup] Feed status init warning: {exc}")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: run startup tasks before yielding."""
    _init_db()
    yield


app = FastAPI(
    title="CTI Aggregator API",
    description="Cyber Threat Intelligence aggregation and analysis platform",
    version="1.0.0",
    lifespan=lifespan,
)

# ---- CORS ----
_raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173")
cors_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Routers ----
app.include_router(scan_router.router, prefix="/api")
app.include_router(dashboard_router.router, prefix="/api")
app.include_router(feeds_router.router, prefix="/api")
app.include_router(reports_router.router, prefix="/api")
app.include_router(ml_router.router, prefix="/api")
app.include_router(bulk_router.router, prefix="/api")


# ---- Health check ----
@app.get("/api/health")
def health_check():
    """Simple health check endpoint."""
    db_status = "connected"
    try:
        db = SessionLocal()
        db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db.close()
    except OperationalError:
        db_status = "error"

    return {"status": "ok", "db": db_status}
