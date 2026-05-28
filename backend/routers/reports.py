import csv
import io
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from database import get_db
from models.scan_result import ScanResult
from models.ioc import IoC
from utils.response import ok

router = APIRouter()


def _build_query(
    db: Session,
    severity: Optional[str] = None,
    ioc_type: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    search: Optional[str] = None,
):
    """Build a SQLAlchemy query with optional filters applied."""
    q = db.query(ScanResult, IoC).join(IoC, ScanResult.ioc_id == IoC.id)

    if severity:
        q = q.filter(ScanResult.overall_severity == severity)

    if ioc_type:
        q = q.filter(IoC.type == ioc_type)

    if date_from:
        try:
            dt_from = datetime.fromisoformat(date_from)
            q = q.filter(ScanResult.scanned_at >= dt_from)
        except ValueError:
            pass  # ignore malformed date

    if date_to:
        try:
            dt_to = datetime.fromisoformat(date_to)
            q = q.filter(ScanResult.scanned_at <= dt_to)
        except ValueError:
            pass

    if search:
        q = q.filter(IoC.value.ilike(f"%{search}%"))

    return q


def _row_to_dict(sr: ScanResult, ioc: IoC) -> dict:
    return {
        "scan_id": sr.scan_id,
        "ioc_value": ioc.value,
        "ioc_type": ioc.type,
        "overall_severity": sr.overall_severity,
        "threat_score": sr.threat_score,
        "ml_severity": sr.ml_severity,
        "ml_confidence": sr.ml_confidence,
        "scanned_at": sr.scanned_at.isoformat() if sr.scanned_at else None,
    }


@router.get("/reports")
def list_reports(
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=200),
    severity: Optional[str] = Query(default=None),
    ioc_type: Optional[str] = Query(default=None),
    date_from: Optional[str] = Query(default=None),
    date_to: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Return paginated scan results with optional filters."""
    q = _build_query(
        db,
        severity=severity or None,
        ioc_type=ioc_type or None,
        date_from=date_from or None,
        date_to=date_to or None,
        search=search or None,
    )

    total = q.count()

    offset = (page - 1) * limit
    rows = (
        q.order_by(ScanResult.scanned_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    results = [_row_to_dict(sr, ioc) for sr, ioc in rows]

    return ok(
        {
            "total": total,
            "page": page,
            "limit": limit,
            "results": results,
        }
    )


@router.get("/reports/export")
def export_reports(
    severity: Optional[str] = Query(default=None),
    ioc_type: Optional[str] = Query(default=None),
    date_from: Optional[str] = Query(default=None),
    date_to: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
):
    """Export scan results as a CSV file (no pagination)."""
    q = _build_query(
        db,
        severity=severity or None,
        ioc_type=ioc_type or None,
        date_from=date_from or None,
        date_to=date_to or None,
        search=search or None,
    )

    rows = q.order_by(ScanResult.scanned_at.desc()).all()

    output = io.StringIO()
    fieldnames = [
        "scan_id",
        "ioc_value",
        "ioc_type",
        "overall_severity",
        "threat_score",
        "ml_severity",
        "ml_confidence",
        "scanned_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for sr, ioc in rows:
        writer.writerow(_row_to_dict(sr, ioc))

    output.seek(0)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"cti_report_{timestamp}.csv"

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
