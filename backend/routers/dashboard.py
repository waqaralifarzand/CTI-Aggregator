import json
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from ..database import get_db
from ..models.scan_result import ScanResult
from ..models.ioc import IoC
from ..models.feed_result import FeedResult
from ..utils.response import ok

router = APIRouter()

ALL_SEVERITIES = ["critical", "high", "medium", "low", "clean"]


@router.get("/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    total_scans = db.query(func.count(ScanResult.id)).scalar() or 0
    threats_found = db.query(func.count(ScanResult.id)).filter(
        ScanResult.overall_severity != "clean"
    ).scalar() or 0
    critical_alerts = db.query(func.count(ScanResult.id)).filter(
        ScanResult.overall_severity == "critical"
    ).scalar() or 0
    clean_scans = db.query(func.count(ScanResult.id)).filter(
        ScanResult.overall_severity == "clean"
    ).scalar() or 0

    return ok({
        "total_scans": total_scans,
        "threats_found": threats_found,
        "critical_alerts": critical_alerts,
        "clean_scans": clean_scans,
    })


@router.get("/dashboard/activity")
async def get_dashboard_activity(days: int = 7, db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    result = []

    for i in range(days - 1, -1, -1):
        day_start = (now - timedelta(days=i)).replace(hour=0, minute=0, second=0, microsecond=0)
        day_end   = day_start + timedelta(days=1)
        date_str  = day_start.strftime("%Y-%m-%d")

        scans = db.query(func.count(ScanResult.id)).filter(
            ScanResult.scanned_at >= day_start,
            ScanResult.scanned_at < day_end,
        ).scalar() or 0

        threats = db.query(func.count(ScanResult.id)).filter(
            ScanResult.scanned_at >= day_start,
            ScanResult.scanned_at < day_end,
            ScanResult.overall_severity != "clean",
        ).scalar() or 0

        result.append({"date": date_str, "scans": scans, "threats": threats})

    return ok(result)


@router.get("/dashboard/severity-breakdown")
async def get_severity_breakdown(db: Session = Depends(get_db)):
    rows = db.query(ScanResult.overall_severity, func.count(ScanResult.id)).group_by(
        ScanResult.overall_severity
    ).all()

    counts = {sev: 0 for sev in ALL_SEVERITIES}
    for sev, cnt in rows:
        if sev in counts:
            counts[sev] = cnt

    return ok([{"severity": sev, "count": counts[sev]} for sev in ALL_SEVERITIES])


@router.get("/dashboard/ioc-breakdown")
async def get_ioc_breakdown(db: Session = Depends(get_db)):
    rows = db.query(IoC.type, func.count(IoC.id)).group_by(IoC.type).all()
    return ok([{"type": t, "count": c} for t, c in rows])


@router.get("/dashboard/ticker")
async def get_ticker(limit: int = 20, db: Session = Depends(get_db)):
    results = (
        db.query(ScanResult, IoC)
        .join(IoC, ScanResult.ioc_id == IoC.id)
        .filter(ScanResult.overall_severity.in_(["high", "critical"]))
        .order_by(ScanResult.scanned_at.desc())
        .limit(limit)
        .all()
    )

    items = []
    for sr, ioc in results:
        # Grab threat tags from feed_results
        feed_row = (
            db.query(FeedResult)
            .filter(
                FeedResult.scan_result_id == sr.id,
                FeedResult.feed_name == "otx",
            )
            .first()
        )
        tags = []
        if feed_row and feed_row.threat_tags:
            tags = [t.strip() for t in feed_row.threat_tags.split(",") if t.strip()]

        items.append({
            "scan_id": sr.scan_id,
            "ioc_value": ioc.value,
            "ioc_type": ioc.type,
            "severity": sr.overall_severity,
            "tags": tags,
            "scanned_at": sr.scanned_at.isoformat() if sr.scanned_at else None,
        })

    return ok(items)
