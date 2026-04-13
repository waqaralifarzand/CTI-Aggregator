import pandas as pd
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock

from backend.services.detection import DetectionEngine


@pytest.fixture
def mock_db():
    """Mock database session."""
    db = MagicMock()
    db.query.return_value.all.return_value = []
    db.query.return_value.delete.return_value = None
    return db


class TestDuplicateDetection:
    def test_detects_cross_feed_duplicates(self, mock_db):
        engine = DetectionEngine(mock_db)
        df = pd.DataFrame([
            {"id": 1, "ioc_value": "1.2.3.4", "ioc_type": "ip", "source_feed": "urlhaus",
             "first_seen": None, "last_seen": None, "severity": "high", "confidence": 80,
             "malware_family": None, "tags": "[]"},
            {"id": 2, "ioc_value": "1.2.3.4", "ioc_type": "ip", "source_feed": "otx",
             "first_seen": None, "last_seen": None, "severity": "high", "confidence": 70,
             "malware_family": None, "tags": "[]"},
            {"id": 3, "ioc_value": "5.6.7.8", "ioc_type": "ip", "source_feed": "urlhaus",
             "first_seen": None, "last_seen": None, "severity": "low", "confidence": 50,
             "malware_family": None, "tags": "[]"},
        ])
        flags = engine._detect_duplicates(df)
        # 1.2.3.4 appears in 2 feeds -> 2 flags (one per indicator row)
        assert len(flags) == 2
        assert all(f.flag_type == "duplicate_cross_feed" for f in flags)

    def test_no_duplicates(self, mock_db):
        engine = DetectionEngine(mock_db)
        df = pd.DataFrame([
            {"id": 1, "ioc_value": "1.2.3.4", "ioc_type": "ip", "source_feed": "urlhaus",
             "first_seen": None, "last_seen": None, "severity": "high", "confidence": 80,
             "malware_family": None, "tags": "[]"},
        ])
        flags = engine._detect_duplicates(df)
        assert len(flags) == 0


class TestCrossFeedConflict:
    def test_detects_conflict(self, mock_db):
        engine = DetectionEngine(mock_db)
        df = pd.DataFrame([
            {"id": 1, "ioc_value": "1.2.3.4", "ioc_type": "ip", "source_feed": "urlhaus",
             "first_seen": None, "last_seen": None, "severity": "high", "confidence": 80,
             "malware_family": None, "tags": "[]"},
            {"id": 2, "ioc_value": "1.2.3.4", "ioc_type": "ip", "source_feed": "otx",
             "first_seen": None, "last_seen": None, "severity": "low", "confidence": 30,
             "malware_family": None, "tags": "[]"},
        ])
        flags = engine._detect_cross_feed_conflict(df)
        # 50% low ratio > 0.2 threshold
        assert len(flags) == 2
        assert all(f.flag_type == "cross_feed_conflict" for f in flags)


class TestRecencyDecay:
    def test_flags_stale_indicators(self, mock_db):
        engine = DetectionEngine(mock_db)
        old_date = datetime.now(tz=timezone.utc) - timedelta(days=200)
        df = pd.DataFrame([
            {"id": 1, "ioc_value": "1.2.3.4", "ioc_type": "ip", "source_feed": "urlhaus",
             "first_seen": old_date, "last_seen": old_date, "severity": "high",
             "confidence": 80, "malware_family": None, "tags": "[]"},
        ])
        flags = engine._apply_recency_decay(df)
        stale_flags = [f for f in flags if f.flag_type == "stale_recency_decay"]
        assert len(stale_flags) == 1

    def test_no_flags_for_recent(self, mock_db):
        engine = DetectionEngine(mock_db)
        recent = datetime.now(tz=timezone.utc) - timedelta(days=5)
        df = pd.DataFrame([
            {"id": 1, "ioc_value": "1.2.3.4", "ioc_type": "ip", "source_feed": "urlhaus",
             "first_seen": recent, "last_seen": recent, "severity": "high",
             "confidence": 80, "malware_family": None, "tags": "[]"},
        ])
        flags = engine._apply_recency_decay(df)
        assert len(flags) == 0
