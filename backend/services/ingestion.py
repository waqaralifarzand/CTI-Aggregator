import json
import time
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy.orm import Session

from backend.connectors.base import BaseConnector
from backend.connectors.urlhaus import URLhausConnector
from backend.connectors.malwarebazaar import MalwareBazaarConnector
from backend.connectors.alienvault_otx import AlienVaultOTXConnector
from backend.connectors.misp import MISPConnector
from backend.models.indicator import Indicator
from backend.models.feed_run import FeedRun
from backend.models.scan_history import ScanHistory
from backend.services.normalization import normalize_batch
from backend.utils.logging import logger


CONNECTORS = {
    "urlhaus": URLhausConnector,
    "malwarebazaar": MalwareBazaarConnector,
    "alienvault_otx": AlienVaultOTXConnector,
    "misp": MISPConnector,
}


def get_connector(feed_name: str) -> BaseConnector:
    cls = CONNECTORS.get(feed_name)
    if cls is None:
        raise ValueError(f"Unknown feed: {feed_name}. Valid: {list(CONNECTORS.keys())}")
    return cls()


async def ingest_feed(feed_name: str, db: Session, **kwargs) -> FeedRun:
    """Fetch, normalize, and store indicators from a single feed.

    Creates a FeedRun record to track progress.
    Deduplicates on (ioc_value, source_feed): updates existing records.
    """
    feed_run = FeedRun(
        feed_name=feed_name,
        started_at=datetime.now(tz=timezone.utc),
        status="running",
    )
    db.add(feed_run)
    db.commit()
    db.refresh(feed_run)

    start_time = time.time()
    connector = get_connector(feed_name)

    try:
        # Run the connector pipeline
        normalized_records = await connector.run(**kwargs)
        feed_run.records_fetched = len(normalized_records)

        # Apply batch normalization (validation, cleanup)
        df = normalize_batch(normalized_records)
        feed_run.records_normalized = len(df)

        if df.empty:
            feed_run.status = "success"
            feed_run.records_stored = 0
            feed_run.completed_at = datetime.now(tz=timezone.utc)
            feed_run.duration_ms = int((time.time() - start_time) * 1000)
            db.commit()
            return feed_run

        # Store in database with deduplication
        stored = 0
        for _, row in df.iterrows():
            record = row.to_dict()

            # Check for existing record with same ioc_value and source_feed
            existing = (
                db.query(Indicator)
                .filter(
                    Indicator.ioc_value == record["ioc_value"],
                    Indicator.source_feed == record["source_feed"],
                )
                .first()
            )

            if existing:
                # Update existing record
                existing.last_seen = record.get("last_seen") or existing.last_seen
                existing.severity = record.get("severity", existing.severity)
                existing.confidence = record.get("confidence", existing.confidence)
                existing.tags = record.get("tags", existing.tags)
                existing.malware_family = record.get("malware_family") or existing.malware_family
                existing.raw_data = record.get("raw_data", existing.raw_data)
                existing.feed_run_id = feed_run.id
            else:
                # Insert new record
                indicator = Indicator(
                    ioc_value=record["ioc_value"],
                    ioc_type=record["ioc_type"],
                    source_feed=record["source_feed"],
                    source_reference=record.get("source_reference"),
                    first_seen=record.get("first_seen"),
                    last_seen=record.get("last_seen"),
                    severity=record.get("severity", "medium"),
                    confidence=record.get("confidence", 50.0),
                    tags=record.get("tags", "[]"),
                    malware_family=record.get("malware_family"),
                    tlp=record.get("tlp", "white"),
                    raw_data=record.get("raw_data"),
                    feed_run_id=feed_run.id,
                )
                db.add(indicator)
            stored += 1

        db.commit()

        feed_run.records_stored = stored
        feed_run.status = "success"

    except Exception as e:
        logger.error(f"Ingestion failed for {feed_name}: {e}")
        feed_run.status = "failed"
        feed_run.error_message = str(e)

    finally:
        feed_run.completed_at = datetime.now(tz=timezone.utc)
        feed_run.duration_ms = int((time.time() - start_time) * 1000)
        db.commit()
        await connector.close()

    # Log to scan history
    scan = ScanHistory(
        action="fetch",
        feed_name=feed_name,
        details=json.dumps({
            "feed_run_id": feed_run.id,
            "status": feed_run.status,
            "records_stored": feed_run.records_stored,
        }),
    )
    db.add(scan)
    db.commit()

    logger.info(
        f"Ingestion complete: feed={feed_name}, status={feed_run.status}, "
        f"stored={feed_run.records_stored}, duration={feed_run.duration_ms}ms"
    )
    return feed_run


async def ingest_all_feeds(db: Session, **kwargs) -> List[FeedRun]:
    """Run ingestion for all configured feeds sequentially."""
    results = []
    for feed_name in CONNECTORS:
        try:
            feed_run = await ingest_feed(feed_name, db, **kwargs)
            results.append(feed_run)
        except Exception as e:
            logger.error(f"Failed to ingest {feed_name}: {e}")
    return results
