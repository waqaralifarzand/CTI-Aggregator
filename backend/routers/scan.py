import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from database import get_db
from models.ioc import IoC
from models.scan_result import ScanResult
from models.feed_result import FeedResult
from schemas.scan import ScanRequest
from services import aggregator_service
from utils.response import ok, err

router = APIRouter()


@router.post("/scan")
async def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """Run a threat intelligence scan for an IoC value."""
    try:
        result = await aggregator_service.run_scan(request.value)
    except ValueError as e:
        return err(str(e), status_code=422)
    except Exception as e:
        return err(f"Scan failed: {str(e)}", status_code=500)

    ioc_value = result["ioc_value"]
    ioc_type = result["ioc_type"]

    # ---- Upsert IoC ----
    ioc = db.query(IoC).filter(IoC.value == ioc_value).first()
    if ioc is None:
        ioc = IoC(
            value=ioc_value,
            type=ioc_type,
            first_seen=result["scanned_at"],
            last_seen=result["scanned_at"],
            scan_count=1,
        )
        db.add(ioc)
        db.flush()
    else:
        ioc.scan_count = (ioc.scan_count or 0) + 1
        ioc.last_seen = result["scanned_at"]

    # ---- Insert ScanResult ----
    raw_summary = json.dumps(
        {
            "feeds": _serialize_feeds(result["feeds"]),
            "blacklist_status": result["blacklist_status"],
            "recommendations": result["recommendations"],
            "ioc": result["ioc"],
        },
        default=str,
    )

    scan_result = ScanResult(
        scan_id=result["scan_id"],
        ioc_id=ioc.id,
        overall_severity=result["overall_severity"],
        ml_severity=result.get("ml_severity"),
        ml_confidence=result.get("ml_confidence"),
        threat_score=result["threat_score"],
        scanned_at=result["scanned_at"],
        raw_summary=raw_summary,
    )
    db.add(scan_result)
    db.flush()

    # ---- Insert FeedResult rows ----
    feeds = result["feeds"]
    for feed_name, feed_data in feeds.items():
        found = feed_data.get("found", False)

        # Extract tags from whichever key they live under
        tags = (
            feed_data.get("threat_tags")
            or feed_data.get("tags")
            or []
        )
        if isinstance(tags, list):
            threat_tags_str = ",".join(str(t) for t in tags) if tags else None
        else:
            threat_tags_str = str(tags) if tags else None

        feed_result = FeedResult(
            scan_result_id=scan_result.id,
            feed_name=feed_name,
            found=found,
            threat_tags=threat_tags_str,
            raw_data=json.dumps(_safe_serialize(feed_data), default=str),
        )
        db.add(feed_result)

    db.commit()

    response_data = {
        "scan_id": result["scan_id"],
        "ioc": result["ioc"],
        "overall_severity": result["overall_severity"],
        "threat_score": result["threat_score"],
        "ml_severity": result.get("ml_severity"),
        "ml_confidence": result.get("ml_confidence"),
        "scanned_at": result["scanned_at"].isoformat(),
        "feeds": _serialize_feeds(result["feeds"]),
        "blacklist_status": result["blacklist_status"],
        "recommendations": result["recommendations"],
    }

    return ok(response_data)


@router.get("/scan/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    """Fetch a scan result by scan_id."""
    scan_result = (
        db.query(ScanResult)
        .filter(ScanResult.scan_id == scan_id)
        .first()
    )
    if scan_result is None:
        return err("Scan not found", status_code=404)

    try:
        raw = json.loads(scan_result.raw_summary)
    except (ValueError, TypeError):
        raw = {}

    ioc = scan_result.ioc

    data = {
        "scan_id": scan_result.scan_id,
        "ioc": raw.get("ioc", {"value": ioc.value if ioc else "", "type": ioc.type if ioc else ""}),
        "overall_severity": scan_result.overall_severity,
        "threat_score": scan_result.threat_score,
        "ml_severity": scan_result.ml_severity,
        "ml_confidence": scan_result.ml_confidence,
        "scanned_at": scan_result.scanned_at.isoformat(),
        "feeds": raw.get("feeds", {}),
        "blacklist_status": raw.get("blacklist_status", {}),
        "recommendations": raw.get("recommendations", []),
    }
    return ok(data)


@router.get("/scans/recent")
def get_recent_scans(
    limit: int = Query(default=10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Return the most recent N scan results."""
    results = (
        db.query(ScanResult)
        .join(IoC, ScanResult.ioc_id == IoC.id)
        .order_by(ScanResult.scanned_at.desc())
        .limit(limit)
        .all()
    )

    data = [
        {
            "scan_id": sr.scan_id,
            "ioc_value": sr.ioc.value if sr.ioc else "",
            "ioc_type": sr.ioc.type if sr.ioc else "",
            "overall_severity": sr.overall_severity,
            "threat_score": sr.threat_score,
            "ml_severity": sr.ml_severity,
            "ml_confidence": sr.ml_confidence,
            "scanned_at": sr.scanned_at.isoformat(),
        }
        for sr in results
    ]
    return ok(data)


# ---- helpers ----

def _safe_serialize(obj):
    """Recursively replace non-serializable items with their string representations."""
    if isinstance(obj, dict):
        return {k: _safe_serialize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_safe_serialize(i) for i in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _serialize_feeds(feeds: dict) -> dict:
    """Remove raw_data blobs from feed results to keep the response lean."""
    serialized = {}
    for feed_name, feed_data in feeds.items():
        if not isinstance(feed_data, dict):
            serialized[feed_name] = feed_data
            continue
        # Keep everything except the potentially large raw_data key
        serialized[feed_name] = {
            k: _safe_serialize(v) for k, v in feed_data.items() if k != "raw_data"
        }
    return serialized
