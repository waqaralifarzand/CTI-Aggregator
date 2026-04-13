import json
from datetime import datetime, timezone
from typing import List, Dict, Any

import pandas as pd

from backend.utils.logging import logger

VALID_IOC_TYPES = {
    "ip", "domain", "hostname", "url", "hash_md5", "hash_sha1",
    "hash_sha256", "email", "cve", "filename",
}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_TLPS = {"white", "green", "amber", "red"}


def validate_record(record: Dict[str, Any]) -> bool:
    """Check that a normalized record has required fields and valid values."""
    if not record.get("ioc_value"):
        return False
    if record.get("ioc_type") not in VALID_IOC_TYPES:
        return False
    if record.get("severity") not in VALID_SEVERITIES:
        record["severity"] = "medium"
    if record.get("tlp") not in VALID_TLPS:
        record["tlp"] = "white"
    return True


def serialize_tags(record: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize the tags list to a JSON string for DB storage."""
    tags = record.get("tags")
    if isinstance(tags, list):
        record["tags"] = json.dumps(tags)
    elif tags is None:
        record["tags"] = "[]"
    return record


def normalize_timestamps(record: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure all timestamps are UTC datetime objects."""
    for field in ("first_seen", "last_seen"):
        val = record.get(field)
        if isinstance(val, str):
            for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z",
                        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
                try:
                    dt = datetime.strptime(val, fmt)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    record[field] = dt
                    break
                except (ValueError, TypeError):
                    continue
            else:
                record[field] = None
        elif val is not None and not isinstance(val, datetime):
            record[field] = None
    return record


def normalize_batch(records: List[Dict[str, Any]]) -> pd.DataFrame:
    """Validate, clean, and convert a list of normalized indicator dicts to a DataFrame.

    This is applied AFTER connector.normalize() has already mapped fields to
    the unified schema. This function adds validation and final cleanup.
    """
    valid_records = []
    skipped = 0

    for record in records:
        record = normalize_timestamps(record)
        record = serialize_tags(record)

        if not validate_record(record):
            skipped += 1
            continue

        # Clamp confidence
        record["confidence"] = max(0.0, min(100.0, float(record.get("confidence", 50.0))))

        valid_records.append(record)

    if skipped:
        logger.warning(f"Normalization: Skipped {skipped} invalid records.")

    if not valid_records:
        return pd.DataFrame()

    df = pd.DataFrame(valid_records)
    logger.info(f"Normalization: Produced DataFrame with {len(df)} rows.")
    return df
