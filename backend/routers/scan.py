import json
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.ioc import IoC
from ..models.scan_result import ScanResult
from ..models.feed_result import FeedResult
from ..schemas.scan import ScanRequest
from ..services.aggregator_service import run_scan
from ..services.ioc_detector import detect_type
from ..utils.response import ok, err

router = APIRouter()


@router.post("/scan")
async def submit_scan(request: ScanRequest, db: Session = Depends(get_db)):
    try:
        ioc_type = detect_type(request.value)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    try:
        scan_data = await run_scan(request.value)
    except Exception as e:
        return err(f"Scan failed: {str(e)}")

    ioc_value = request.value.strip()

    # Upsert IoC record
    ioc = db.query(IoC).filter(IoC.value == ioc_value).first()
    if ioc:
        ioc.scan_count += 1
        ioc.last_seen = datetime.now(timezone.utc)
    else:
        ioc = IoC(
            value=ioc_value,
            type=ioc_type,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            scan_count=1,
        )
        db.add(ioc)
        db.flush()

    # Create ScanResult row
    scan_result = ScanResult(
        scan_id=scan_data["scan_id"],
        ioc_id=ioc.id,
        overall_severity=scan_data["overall_severity"],
        ml_severity=scan_data.get("ml_severity"),
        ml_confidence=scan_data.get("ml_confidence"),
        threat_score=scan_data["threat_score"],
        scanned_at=datetime.now(timezone.utc),
        raw_summary=json.dumps(scan_data),
    )
    db.add(scan_result)
    db.flush()

    # Create FeedResult rows
    feeds = scan_data.get("feeds", {})
    for feed_name, feed_data in feeds.items():
        if feed_data is None:
            continue
        found = feed_data.get("found", False) if isinstance(feed_data, dict) else False
        tags = feed_data.get("threat_tags") or feed_data.get("tags") or []
        threat_tags_str = ",".join(str(t) for t in tags) if tags else None

        db.add(FeedResult(
            scan_result_id=scan_result.id,
            feed_name=feed_name,
            found=found,
            threat_tags=threat_tags_str,
            raw_data=json.dumps(feed_data),
        ))

    db.commit()
    return ok(scan_data)


@router.get("/scans/recent")
async def recent_scans(limit: int = 10, db: Session = Depends(get_db)):
    results = (
        db.query(ScanResult, IoC)
        .join(IoC, ScanResult.ioc_id == IoC.id)
        .order_by(ScanResult.scanned_at.desc())
        .limit(limit)
        .all()
    )
    items = [
        {
            "scan_id": sr.scan_id,
            "ioc_value": ioc.value,
            "ioc_type": ioc.type,
            "overall_severity": sr.overall_severity,
            "threat_score": sr.threat_score,
            "scanned_at": sr.scanned_at.isoformat() if sr.scanned_at else None,
        }
        for sr, ioc in results
    ]
    return ok(items)


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan_result = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).first()
    if not scan_result:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        data = json.loads(scan_result.raw_summary)
    except Exception:
        data = {"scan_id": scan_id, "error": "Could not parse scan data"}

    return ok(data)
