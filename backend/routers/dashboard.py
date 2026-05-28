from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, case
from sqlalchemy.orm import Session

from database import get_db
from models.scan_result import ScanResult
from models.ioc import IoC
from models.feed_result import FeedResult
from utils.response import ok

router = APIRouter()


@router.get("/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Return high-level dashboard statistics."""
    total_scans = db.query(func.count(ScanResult.id)).scalar() or 0

    threats_found = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.overall_severity != "clean")
        .scalar()
        or 0
    )

    critical_alerts = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.overall_severity == "critical")
        .scalar()
        or 0
    )

    clean_scans = (
        db.query(func.count(ScanResult.id))
        .filter(ScanResult.overall_severity == "clean")
        .scalar()
        or 0
    )

    return ok(
        {
            "total_scans": total_scans,
            "threats_found": threats_found,
            "critical_alerts": critical_alerts,
            "clean_scans": clean_scans,
        }
    )


@router.get("/dashboard/activity")
def get_dashboard_activity(
    days: int = Query(default=7, ge=1, le=90),
    db: Session = Depends(get_db),
):
    """Return scan/threat counts grouped by date for the last N days."""
    since = datetime.utcnow() - timedelta(days=days)

    rows = (
        db.query(
            func.date(ScanResult.scanned_at).label("date"),
            func.count(ScanResult.id).label("scans"),
            func.sum(
                case(
                    (ScanResult.overall_severity != "clean", 1),
                    else_=0,
                )
            ).label("threats"),
        )
        .filter(ScanResult.scanned_at >= since)
        .group_by(func.date(ScanResult.scanned_at))
        .order_by(func.date(ScanResult.scanned_at).asc())
        .all()
    )

    # Build a dict keyed by date so we can fill in zeros for missing days
    data_map = {}
    for row in rows:
        date_str = str(row.date)
        data_map[date_str] = {
            "date": date_str,
            "scans": int(row.scans or 0),
            "threats": int(row.threats or 0),
        }

    # Fill in missing days with zeros
    result = []
    for i in range(days):
        day = (datetime.utcnow() - timedelta(days=days - 1 - i)).strftime("%Y-%m-%d")
        result.append(
            data_map.get(
                day,
                {"date": day, "scans": 0, "threats": 0},
            )
        )

    return ok(result)


@router.get("/dashboard/severity-breakdown")
def get_severity_breakdown(db: Session = Depends(get_db)):
    """Return scan counts grouped by severity."""
    rows = (
        db.query(
            ScanResult.overall_severity.label("severity"),
            func.count(ScanResult.id).label("count"),
        )
        .group_by(ScanResult.overall_severity)
        .all()
    )

    data = [{"severity": row.severity, "count": int(row.count)} for row in rows]

    # Ensure all severity levels are represented
    all_severities = ["clean", "low", "medium", "high", "critical"]
    existing = {d["severity"] for d in data}
    for sev in all_severities:
        if sev not in existing:
            data.append({"severity": sev, "count": 0})

    # Sort by natural threat order
    order = {s: i for i, s in enumerate(all_severities)}
    data.sort(key=lambda x: order.get(x["severity"], 99))

    return ok(data)


@router.get("/dashboard/ioc-breakdown")
def get_ioc_breakdown(db: Session = Depends(get_db)):
    """Return IoC counts grouped by type."""
    rows = (
        db.query(
            IoC.type.label("ioc_type"),
            func.count(IoC.id).label("count"),
        )
        .group_by(IoC.type)
        .all()
    )

    data = [{"ioc_type": row.ioc_type, "count": int(row.count)} for row in rows]
    return ok(data)


@router.get("/dashboard/ticker")
def get_dashboard_ticker(
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Return the latest high/critical severity scan results for the ticker."""
    results = (
        db.query(ScanResult)
        .join(IoC, ScanResult.ioc_id == IoC.id)
        .filter(ScanResult.overall_severity.in_(["high", "critical"]))
        .order_by(ScanResult.scanned_at.desc())
        .limit(limit)
        .all()
    )

    ticker = []
    for sr in results:
        # Gather tags from feed_results
        tags = []
        for fr in sr.feed_results:
            if fr.threat_tags:
                for tag in fr.threat_tags.split(","):
                    tag = tag.strip()
                    if tag and tag not in tags:
                        tags.append(tag)

        ticker.append(
            {
                "ioc_value": sr.ioc.value if sr.ioc else "",
                "ioc_type": sr.ioc.type if sr.ioc else "",
                "severity": sr.overall_severity,
                "tags": tags[:5],  # cap to keep response lean
                "scanned_at": sr.scanned_at.isoformat(),
            }
        )

    return ok(ticker)
