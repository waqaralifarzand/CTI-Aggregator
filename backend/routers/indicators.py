import csv
import io
import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, func

from backend.database import get_db
from backend.models.indicator import Indicator
from backend.schemas.indicator import (
    IndicatorRead, IndicatorDetail, IndicatorList, IndicatorSearch,
)

router = APIRouter()


def _parse_tags(indicator: Indicator) -> IndicatorRead:
    """Convert DB row to response model, deserializing JSON tags."""
    tags = []
    if indicator.tags:
        try:
            tags = json.loads(indicator.tags)
        except (json.JSONDecodeError, TypeError):
            tags = []
    return IndicatorRead(
        id=indicator.id,
        ioc_value=indicator.ioc_value,
        ioc_type=indicator.ioc_type,
        source_feed=indicator.source_feed,
        source_reference=indicator.source_reference,
        first_seen=indicator.first_seen,
        last_seen=indicator.last_seen,
        severity=indicator.severity,
        confidence=indicator.confidence,
        tags=tags,
        malware_family=indicator.malware_family,
        tlp=indicator.tlp,
        created_at=indicator.created_at,
        updated_at=indicator.updated_at,
    )


@router.get("", response_model=IndicatorList)
def list_indicators(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_feed: Optional[str] = None,
    search: Optional[str] = None,
    sort_by: str = "created_at",
    order: str = "desc",
    db: Session = Depends(get_db),
):
    """List indicators with filtering, pagination, and sorting."""
    query = db.query(Indicator)

    if ioc_type:
        query = query.filter(Indicator.ioc_type == ioc_type)
    if severity:
        query = query.filter(Indicator.severity == severity)
    if source_feed:
        query = query.filter(Indicator.source_feed == source_feed)
    if search:
        query = query.filter(
            (Indicator.ioc_value.contains(search))
            | (Indicator.malware_family.contains(search))
            | (Indicator.tags.contains(search))
        )

    total = query.count()

    # Sorting
    sort_column = getattr(Indicator, sort_by, Indicator.created_at)
    if order == "asc":
        query = query.order_by(asc(sort_column))
    else:
        query = query.order_by(desc(sort_column))

    # Pagination
    offset = (page - 1) * per_page
    indicators = query.offset(offset).limit(per_page).all()

    items = [_parse_tags(ind) for ind in indicators]
    return IndicatorList(total=total, page=page, per_page=per_page, items=items)


@router.get("/search", response_model=IndicatorSearch)
def search_indicator(value: str, db: Session = Depends(get_db)):
    """Search for an IoC value across all feeds."""
    indicators = db.query(Indicator).filter(Indicator.ioc_value == value).all()
    items = [_parse_tags(ind) for ind in indicators]
    return IndicatorSearch(value=value, results=items)


@router.get("/export")
def export_indicators(
    ioc_type: Optional[str] = None,
    severity: Optional[str] = None,
    source_feed: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """Export indicators as CSV."""
    query = db.query(Indicator)
    if ioc_type:
        query = query.filter(Indicator.ioc_type == ioc_type)
    if severity:
        query = query.filter(Indicator.severity == severity)
    if source_feed:
        query = query.filter(Indicator.source_feed == source_feed)

    indicators = query.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "ioc_value", "ioc_type", "source_feed", "severity",
        "confidence", "malware_family", "tlp", "first_seen", "last_seen",
    ])
    for ind in indicators:
        writer.writerow([
            ind.id, ind.ioc_value, ind.ioc_type, ind.source_feed, ind.severity,
            ind.confidence, ind.malware_family, ind.tlp, ind.first_seen, ind.last_seen,
        ])

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=indicators.csv"},
    )


@router.get("/{indicator_id}", response_model=IndicatorDetail)
def get_indicator(indicator_id: int, db: Session = Depends(get_db)):
    """Get a single indicator with full detail."""
    indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")

    tags = []
    if indicator.tags:
        try:
            tags = json.loads(indicator.tags)
        except (json.JSONDecodeError, TypeError):
            tags = []

    return IndicatorDetail(
        id=indicator.id,
        ioc_value=indicator.ioc_value,
        ioc_type=indicator.ioc_type,
        source_feed=indicator.source_feed,
        source_reference=indicator.source_reference,
        first_seen=indicator.first_seen,
        last_seen=indicator.last_seen,
        severity=indicator.severity,
        confidence=indicator.confidence,
        tags=tags,
        malware_family=indicator.malware_family,
        tlp=indicator.tlp,
        raw_data=indicator.raw_data,
        feed_run_id=indicator.feed_run_id,
        created_at=indicator.created_at,
        updated_at=indicator.updated_at,
    )
