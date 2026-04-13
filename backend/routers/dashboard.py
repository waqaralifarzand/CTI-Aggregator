from datetime import datetime, timedelta, timezone
from typing import List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.database import get_db
from backend.models.indicator import Indicator
from backend.models.feed_run import FeedRun
from backend.models.scan_history import ScanHistory
from backend.schemas.dashboard import (
    DashboardSummary, DashboardTimeline, TimelinePoint,
    TopIoC, FeedHealth, RecentActivity,
)
from backend.services.ingestion import CONNECTORS

router = APIRouter()


@router.get("/summary", response_model=DashboardSummary)
def get_summary(db: Session = Depends(get_db)):
    """High-level statistics for the dashboard."""
    total = db.query(func.count(Indicator.id)).scalar() or 0

    # By severity
    severity_rows = (
        db.query(Indicator.severity, func.count(Indicator.id))
        .group_by(Indicator.severity)
        .all()
    )
    by_severity = {row[0]: row[1] for row in severity_rows}

    # By source
    source_rows = (
        db.query(Indicator.source_feed, func.count(Indicator.id))
        .group_by(Indicator.source_feed)
        .all()
    )
    by_source = {row[0]: row[1] for row in source_rows}

    # By type
    type_rows = (
        db.query(Indicator.ioc_type, func.count(Indicator.id))
        .group_by(Indicator.ioc_type)
        .all()
    )
    by_type = {row[0]: row[1] for row in type_rows}

    return DashboardSummary(
        total_indicators=total,
        by_severity=by_severity,
        by_source=by_source,
        by_type=by_type,
    )


@router.get("/timeline", response_model=DashboardTimeline)
def get_timeline(days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db)):
    """Indicator counts over time for charting."""
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=days)

    indicators = (
        db.query(Indicator)
        .filter(Indicator.created_at >= cutoff)
        .all()
    )

    # Aggregate by date
    date_map = {}
    for ind in indicators:
        if ind.created_at is None:
            continue
        date_str = ind.created_at.strftime("%Y-%m-%d")
        if date_str not in date_map:
            date_map[date_str] = {"count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        date_map[date_str]["count"] += 1
        sev = ind.severity if ind.severity in ("critical", "high", "medium", "low") else "medium"
        date_map[date_str][sev] += 1

    data = [
        TimelinePoint(date=d, **counts)
        for d, counts in sorted(date_map.items())
    ]
    return DashboardTimeline(data=data)


@router.get("/top-iocs", response_model=List[TopIoC])
def get_top_iocs(limit: int = Query(10, ge=1, le=100), db: Session = Depends(get_db)):
    """Most reported IoCs (by number of source feeds)."""
    rows = (
        db.query(
            Indicator.ioc_value,
            Indicator.ioc_type,
            func.count(func.distinct(Indicator.source_feed)).label("num_sources"),
            func.max(Indicator.severity).label("severity"),
            Indicator.malware_family,
        )
        .group_by(Indicator.ioc_value, Indicator.ioc_type, Indicator.malware_family)
        .order_by(desc("num_sources"))
        .limit(limit)
        .all()
    )

    return [
        TopIoC(
            ioc_value=row[0],
            ioc_type=row[1],
            num_sources=row[2],
            severity=row[3],
            malware_family=row[4],
        )
        for row in rows
    ]


@router.get("/feed-health", response_model=List[FeedHealth])
def get_feed_health(db: Session = Depends(get_db)):
    """Feed operational health statistics."""
    results = []
    for feed_name in CONNECTORS:
        runs = (
            db.query(FeedRun)
            .filter(FeedRun.feed_name == feed_name)
            .order_by(desc(FeedRun.started_at))
            .limit(20)
            .all()
        )
        total_runs = len(runs)
        if total_runs == 0:
            results.append(FeedHealth(feed=feed_name))
            continue

        last_success = None
        success_durations = []
        error_count = 0

        for run in runs:
            if run.status == "success":
                if last_success is None:
                    last_success = run.started_at
                if run.duration_ms:
                    success_durations.append(run.duration_ms)
            elif run.status == "failed":
                error_count += 1

        avg_time = sum(success_durations) / len(success_durations) if success_durations else None
        error_rate = error_count / total_runs if total_runs else 0.0

        results.append(FeedHealth(
            feed=feed_name,
            last_success=last_success,
            avg_fetch_time_ms=avg_time,
            error_rate=error_rate,
            total_runs=total_runs,
        ))

    return results


@router.get("/recent-activity", response_model=List[RecentActivity])
def get_recent_activity(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    """Recent system activity (fetches, detections, etc)."""
    scans = (
        db.query(ScanHistory)
        .order_by(desc(ScanHistory.performed_at))
        .limit(limit)
        .all()
    )
    return [
        RecentActivity(
            timestamp=s.performed_at,
            event=s.action,
            feed=s.feed_name,
            details=s.details,
        )
        for s in scans
    ]
