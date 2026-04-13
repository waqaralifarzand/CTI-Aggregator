from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.database import get_db
from backend.models.feed_run import FeedRun
from backend.schemas.feed import (
    FeedFetchRequest, FeedFetchResponse, FeedStatus, FeedStatusList, FeedRunRead,
)
from backend.services.ingestion import ingest_feed, ingest_all_feeds, CONNECTORS

router = APIRouter()


@router.post("/fetch", response_model=FeedFetchResponse)
async def trigger_fetch(request: FeedFetchRequest, db: Session = Depends(get_db)):
    """Trigger a fetch from one or all feeds."""
    feed_run_ids = []

    if request.feed == "all":
        runs = await ingest_all_feeds(db)
        feed_run_ids = [r.id for r in runs]
        message = f"Fetched from {len(runs)} feeds."
    else:
        if request.feed not in CONNECTORS:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown feed: {request.feed}. Valid: {list(CONNECTORS.keys())}",
            )
        run = await ingest_feed(request.feed, db)
        feed_run_ids = [run.id]
        message = f"Fetched from {request.feed}: {run.records_stored} records stored."

    return FeedFetchResponse(status="completed", feed_run_ids=feed_run_ids, message=message)


@router.get("/status", response_model=FeedStatusList)
def get_all_feed_status(db: Session = Depends(get_db)):
    """Get the latest status for all feeds."""
    feeds = []
    for feed_name in CONNECTORS:
        latest = (
            db.query(FeedRun)
            .filter(FeedRun.feed_name == feed_name)
            .order_by(desc(FeedRun.started_at))
            .first()
        )
        if latest:
            feeds.append(FeedStatus(
                feed=feed_name,
                last_run=latest.started_at,
                records_fetched=latest.records_fetched,
                status=latest.status,
                duration_ms=latest.duration_ms,
                error_message=latest.error_message,
            ))
        else:
            feeds.append(FeedStatus(feed=feed_name))
    return FeedStatusList(feeds=feeds)


@router.get("/status/{feed_name}", response_model=FeedStatus)
def get_feed_status(feed_name: str, db: Session = Depends(get_db)):
    """Get detailed status for a single feed."""
    if feed_name not in CONNECTORS:
        raise HTTPException(status_code=404, detail=f"Unknown feed: {feed_name}")

    latest = (
        db.query(FeedRun)
        .filter(FeedRun.feed_name == feed_name)
        .order_by(desc(FeedRun.started_at))
        .first()
    )
    if latest:
        return FeedStatus(
            feed=feed_name,
            last_run=latest.started_at,
            records_fetched=latest.records_fetched,
            status=latest.status,
            duration_ms=latest.duration_ms,
            error_message=latest.error_message,
        )
    return FeedStatus(feed=feed_name)


@router.get("/history", response_model=List[FeedRunRead])
def get_feed_history(limit: int = 20, db: Session = Depends(get_db)):
    """Get recent feed run history."""
    runs = (
        db.query(FeedRun)
        .order_by(desc(FeedRun.started_at))
        .limit(limit)
        .all()
    )
    return runs
