import csv
import io
import json
import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, File, UploadFile
from sqlalchemy.orm import Session

from database import get_db, SessionLocal
from models.bulk_job import BulkJob
from models.ioc import IoC
from models.scan_result import ScanResult
from models.feed_result import FeedResult
from services import aggregator_service
from utils.response import ok, err

router = APIRouter()


async def _process_bulk_job(job_id: str, ioc_values: list[str]):
    """Background task: scan each IoC and update the BulkJob record."""
    db = SessionLocal()
    try:
        job = db.query(BulkJob).filter(BulkJob.job_id == job_id).first()
        if job is None:
            return

        job.status = "running"
        db.commit()

        for value in ioc_values:
            value = value.strip()
            if not value:
                job.failed = (job.failed or 0) + 1
                db.commit()
                continue

            try:
                result = await aggregator_service.run_scan(value)

                # Upsert IoC
                ioc = db.query(IoC).filter(IoC.value == result["ioc_value"]).first()
                if ioc is None:
                    ioc = IoC(
                        value=result["ioc_value"],
                        type=result["ioc_type"],
                        first_seen=result["scanned_at"],
                        last_seen=result["scanned_at"],
                        scan_count=1,
                    )
                    db.add(ioc)
                    db.flush()
                else:
                    ioc.scan_count = (ioc.scan_count or 0) + 1
                    ioc.last_seen = result["scanned_at"]

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
                    bulk_job_id=job_id,
                )
                db.add(scan_result)
                db.flush()

                for feed_name, feed_data in result["feeds"].items():
                    found = feed_data.get("found", False)
                    tags = feed_data.get("threat_tags") or feed_data.get("tags") or []
                    threat_tags_str = (
                        ",".join(str(t) for t in tags) if tags else None
                    )
                    feed_result = FeedResult(
                        scan_result_id=scan_result.id,
                        feed_name=feed_name,
                        found=found,
                        threat_tags=threat_tags_str,
                        raw_data=json.dumps(
                            {k: v for k, v in feed_data.items() if k != "raw_data"},
                            default=str,
                        ),
                    )
                    db.add(feed_result)

                job.completed = (job.completed or 0) + 1
            except Exception:
                job.failed = (job.failed or 0) + 1

            db.commit()

        job.status = "completed"
        job.finished_at = datetime.utcnow()
        db.commit()

    except Exception:
        job = db.query(BulkJob).filter(BulkJob.job_id == job_id).first()
        if job:
            job.status = "failed"
            job.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


@router.post("/bulk/scan")
async def bulk_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    """Accept a CSV file of IoC values and start a bulk scan job."""
    if not file.filename or not file.filename.endswith(".csv"):
        return err("Only CSV files are accepted", status_code=400)

    content = await file.read()
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    # Parse CSV — accept single-column or multi-column; first column is the IoC
    reader = csv.reader(io.StringIO(text))
    ioc_values = []
    for row in reader:
        if not row:
            continue
        value = row[0].strip()
        # Skip header-ish rows
        if value.lower() in ("ioc", "value", "indicator", "ioc_value", "#"):
            continue
        if value:
            ioc_values.append(value)

    if not ioc_values:
        return err("No IoC values found in the uploaded CSV", status_code=400)

    # Cap at 500 entries per job to prevent runaway tasks
    MAX_IOCS = 500
    if len(ioc_values) > MAX_IOCS:
        ioc_values = ioc_values[:MAX_IOCS]

    job_id = str(uuid.uuid4())
    job = BulkJob(
        job_id=job_id,
        total=len(ioc_values),
        completed=0,
        failed=0,
        status="pending",
        created_at=datetime.utcnow(),
    )
    db.add(job)
    db.commit()

    background_tasks.add_task(_process_bulk_job, job_id, ioc_values)

    return ok(
        {
            "job_id": job_id,
            "total": len(ioc_values),
            "status": "pending",
            "message": f"Bulk scan started for {len(ioc_values)} IoC(s).",
        }
    )


@router.get("/bulk/{job_id}")
def get_bulk_job(job_id: str, db: Session = Depends(get_db)):
    """Return the status and results of a bulk scan job."""
    job = db.query(BulkJob).filter(BulkJob.job_id == job_id).first()
    if job is None:
        return err("Job not found", status_code=404)

    # Fetch associated scan results
    rows = (
        db.query(ScanResult, IoC)
        .join(IoC, ScanResult.ioc_id == IoC.id)
        .filter(ScanResult.bulk_job_id == job_id)
        .order_by(ScanResult.scanned_at.asc())
        .all()
    )

    results = [
        {
            "scan_id": sr.scan_id,
            "ioc_value": ioc.value,
            "ioc_type": ioc.type,
            "overall_severity": sr.overall_severity,
            "ml_severity": sr.ml_severity,
            "threat_score": sr.threat_score,
        }
        for sr, ioc in rows
    ]

    return ok(
        {
            "job_id": job.job_id,
            "total": job.total,
            "completed": job.completed,
            "failed": job.failed,
            "status": job.status,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "results": results,
        }
    )


# ---- helper ----

def _serialize_feeds(feeds: dict) -> dict:
    result = {}
    for feed_name, feed_data in feeds.items():
        if not isinstance(feed_data, dict):
            result[feed_name] = feed_data
            continue
        result[feed_name] = {k: v for k, v in feed_data.items() if k != "raw_data"}
    return result
