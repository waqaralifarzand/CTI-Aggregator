import json
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from backend.database import get_db
from backend.models.anomaly_flag import AnomalyFlag
from backend.models.indicator import Indicator
from backend.models.scan_history import ScanHistory
from backend.schemas.anomaly import AnomalyFlagRead, AnomalyList, AnomalySummary, AnomalyRunResponse
from backend.services.detection import DetectionEngine

router = APIRouter()


@router.post("/run", response_model=AnomalyRunResponse)
def run_detection(db: Session = Depends(get_db)):
    """Trigger the detection engine on all current indicators."""
    engine = DetectionEngine(db)
    flags_generated = engine.run_and_store()

    # Log to scan history
    scan = ScanHistory(
        action="detect",
        details=json.dumps({"flags_generated": flags_generated}),
    )
    db.add(scan)
    db.commit()

    return AnomalyRunResponse(status="completed", flags_generated=flags_generated)


@router.get("", response_model=AnomalyList)
def list_anomalies(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    flag_type: Optional[str] = None,
    min_score: float | None = None,
    db: Session = Depends(get_db),
):
    """List anomaly flags with optional filtering."""
    query = db.query(AnomalyFlag)

    if flag_type:
        query = query.filter(AnomalyFlag.flag_type == flag_type)
    if min_score is not None:
        query = query.filter(AnomalyFlag.anomaly_score >= min_score)

    total = query.count()
    offset = (page - 1) * per_page
    items = query.order_by(desc(AnomalyFlag.detected_at)).offset(offset).limit(per_page).all()

    return AnomalyList(
        total=total,
        page=page,
        per_page=per_page,
        items=[AnomalyFlagRead.model_validate(f) for f in items],
    )


@router.get("/summary", response_model=AnomalySummary)
def get_anomaly_summary(db: Session = Depends(get_db)):
    """Aggregated anomaly statistics."""
    total = db.query(func.count(AnomalyFlag.id)).scalar() or 0

    type_rows = (
        db.query(AnomalyFlag.flag_type, func.count(AnomalyFlag.id))
        .group_by(AnomalyFlag.flag_type)
        .all()
    )
    by_type = {row[0]: row[1] for row in type_rows}

    return AnomalySummary(total_flags=total, by_type=by_type)
