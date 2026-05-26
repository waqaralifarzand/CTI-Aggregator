import os
import httpx
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.feed_status import FeedStatus
from ..utils.response import ok, err

router = APIRouter()

FEED_DISPLAY_NAMES = {
    "otx": "AlienVault OTX",
    "urlhaus": "Abuse.ch URLhaus",
    "malwarebazaar": "Abuse.ch MalwareBazaar",
    "virustotal": "VirusTotal",
}

ALL_FEEDS = list(FEED_DISPLAY_NAMES.keys())


def _upsert_feed_status(db: Session, feed_name: str, status: str = "unknown",
                        error_message: str | None = None, record_count: int = 0):
    row = db.query(FeedStatus).filter(FeedStatus.feed_name == feed_name).first()
    if row:
        row.status = status
        row.updated_at = datetime.now(timezone.utc)
        if error_message is not None:
            row.error_message = error_message
        if record_count > 0:
            row.record_count = record_count
    else:
        row = FeedStatus(
            feed_name=feed_name,
            status=status,
            error_message=error_message,
            record_count=record_count,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(row)
    db.commit()
    return row


async def _ping_feed(feed_name: str) -> tuple[str, str | None]:
    try:
        if feed_name == "otx":
            api_key = os.getenv("OTX_API_KEY", "")
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(
                    "https://otx.alienvault.com/api/v1/user/me",
                    headers={"X-OTX-API-KEY": api_key},
                )
            if resp.status_code == 200:
                return "active", None
            return "error", f"HTTP {resp.status_code}"

        elif feed_name == "urlhaus":
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(
                    "https://urlhaus-api.abuse.ch/v1/host/",
                    data={"host": "8.8.8.8"},
                )
            if resp.status_code == 200:
                return "active", None
            return "error", f"HTTP {resp.status_code}"

        elif feed_name == "malwarebazaar":
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={"query": "get_info", "hash": "44d88612fea8a8f36de82e1278abb02f"},
                )
            if resp.status_code == 200:
                return "active", None
            return "error", f"HTTP {resp.status_code}"

        elif feed_name == "virustotal":
            api_key = os.getenv("VT_API_KEY", "")
            if not api_key or api_key == "placeholder_key":
                return "error", "VT_API_KEY not configured"
            async with httpx.AsyncClient(timeout=8) as client:
                resp = await client.get(
                    "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
                    headers={"x-apikey": api_key},
                )
            if resp.status_code == 200:
                return "active", None
            if resp.status_code == 401:
                return "error", "Invalid VT API key"
            return "error", f"HTTP {resp.status_code}"

    except Exception as e:
        return "error", str(e)

    return "error", "Unknown feed"


@router.get("/feeds")
async def get_feeds(db: Session = Depends(get_db)):
    rows = db.query(FeedStatus).all()
    result = []
    for row in rows:
        result.append({
            "feed_name": row.feed_name,
            "display_name": FEED_DISPLAY_NAMES.get(row.feed_name, row.feed_name),
            "status": row.status,
            "last_synced": row.last_synced.isoformat() if row.last_synced else None,
            "record_count": row.record_count,
            "error_message": row.error_message,
        })
    return ok(result)


@router.post("/feeds/{feed_name}/refresh")
async def refresh_feed(feed_name: str, db: Session = Depends(get_db)):
    if feed_name not in ALL_FEEDS:
        return err(f"Unknown feed: {feed_name}")

    status, error_message = await _ping_feed(feed_name)

    row = db.query(FeedStatus).filter(FeedStatus.feed_name == feed_name).first()
    if row:
        row.status = status
        row.error_message = error_message
        row.updated_at = datetime.now(timezone.utc)
        if status == "active":
            row.last_synced = datetime.now(timezone.utc)
    else:
        row = FeedStatus(
            feed_name=feed_name,
            status=status,
            error_message=error_message,
            last_synced=datetime.now(timezone.utc) if status == "active" else None,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(row)
    db.commit()

    message = "Feed verified successfully." if status == "active" else f"Feed check failed: {error_message}"
    return ok({"feed_name": feed_name, "status": status, "message": message})
