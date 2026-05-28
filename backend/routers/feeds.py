from datetime import datetime

import httpx
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models.feed_status import FeedStatus
from utils.response import ok, err

router = APIRouter()

# Simple health-check endpoints for each feed
_FEED_HEALTH_CHECKS = {
    "otx": {
        "method": "GET",
        "url": "https://otx.alienvault.com/api/v1/user/me",
        "headers_fn": lambda: {"X-OTX-API-KEY": _get_otx_key()},
    },
    "urlhaus": {
        "method": "POST",
        "url": "https://urlhaus-api.abuse.ch/v1/host/",
        "data": {"host": "example.com"},
    },
    "malwarebazaar": {
        "method": "POST",
        "url": "https://mb-api.abuse.ch/api/v1/",
        "data": {"query": "get_info", "hash": "aabbccdd"},
    },
}


def _get_otx_key() -> str:
    import os
    return os.getenv("OTX_API_KEY", "")


@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db)):
    """Return all feed status rows."""
    feeds = db.query(FeedStatus).order_by(FeedStatus.feed_name).all()
    data = [
        {
            "id": f.id,
            "feed_name": f.feed_name,
            "status": f.status,
            "last_synced": f.last_synced.isoformat() if f.last_synced else None,
            "record_count": f.record_count,
            "error_message": f.error_message,
            "updated_at": f.updated_at.isoformat() if f.updated_at else None,
        }
        for f in feeds
    ]
    return ok(data)


@router.post("/feeds/{feed_name}/refresh")
async def refresh_feed(feed_name: str, db: Session = Depends(get_db)):
    """Make a test API call to the named feed and update its status."""
    check = _FEED_HEALTH_CHECKS.get(feed_name)
    if check is None:
        return err(f"Unknown feed: {feed_name}", status_code=404)

    feed_status = db.query(FeedStatus).filter(FeedStatus.feed_name == feed_name).first()
    if feed_status is None:
        feed_status = FeedStatus(feed_name=feed_name)
        db.add(feed_status)

    now = datetime.utcnow()
    error_message = None
    status = "online"
    record_count = feed_status.record_count or 0

    try:
        headers = {}
        if "headers_fn" in check:
            headers = check["headers_fn"]()

        async with httpx.AsyncClient(timeout=10.0) as client:
            if check["method"] == "GET":
                resp = await client.get(check["url"], headers=headers)
            else:
                resp = await client.post(
                    check["url"],
                    data=check.get("data", {}),
                    headers=headers,
                )

        if resp.status_code in (200, 201, 204):
            status = "online"
            # Try to extract a record count hint from the response
            try:
                body = resp.json()
                if feed_name == "otx":
                    # OTX user endpoint — just use existing count
                    pass
                elif feed_name == "urlhaus":
                    urls = body.get("urls", [])
                    if urls:
                        record_count = len(urls)
                elif feed_name == "malwarebazaar":
                    data_list = body.get("data", [])
                    if data_list:
                        record_count = len(data_list)
            except Exception:
                pass
        elif resp.status_code == 401:
            status = "auth_error"
            error_message = "Authentication failed — check API key"
        elif resp.status_code == 404:
            status = "online"  # 404 on a hash/host just means not found, service is up
        else:
            status = "degraded"
            error_message = f"Unexpected HTTP {resp.status_code}"

    except httpx.TimeoutException:
        status = "timeout"
        error_message = "Connection timed out"
    except httpx.RequestError as exc:
        status = "offline"
        error_message = str(exc)
    except Exception as exc:
        status = "error"
        error_message = str(exc)

    feed_status.status = status
    feed_status.last_synced = now
    feed_status.record_count = record_count
    feed_status.error_message = error_message
    feed_status.updated_at = now
    db.commit()

    return ok(
        {
            "feed_name": feed_name,
            "status": status,
            "message": f"Feed '{feed_name}' refreshed successfully"
            if error_message is None
            else f"Feed '{feed_name}' refresh completed with issues",
            "last_synced": now.isoformat(),
            "record_count": record_count,
            "error_message": error_message,
        }
    )
