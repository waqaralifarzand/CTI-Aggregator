import pandas as pd
import pytest
from datetime import datetime, timezone

from backend.ml.features import extract_features, FEATURE_COLUMNS
from backend.ml.predict import Predictor


class TestFeatureExtraction:
    def test_output_columns(self):
        df = pd.DataFrame([{
            "ioc_value": "1.2.3.4",
            "ioc_type": "ip",
            "source_feed": "urlhaus",
            "first_seen": datetime(2026, 3, 1, tzinfo=timezone.utc),
            "last_seen": datetime(2026, 3, 15, tzinfo=timezone.utc),
            "confidence": 85.0,
            "tags": '["test"]',
            "malware_family": "Emotet",
            "tlp": "green",
            "severity": "high",
        }])
        features = extract_features(df)
        assert list(features.columns) == FEATURE_COLUMNS
        assert len(features) == 1

    def test_ioc_type_encoding(self):
        records = [
            {"ioc_value": "1.2.3.4", "ioc_type": "ip", "source_feed": "test",
             "first_seen": None, "last_seen": None, "confidence": 50, "tags": "[]",
             "malware_family": None, "tlp": "white", "severity": "medium"},
            {"ioc_value": "evil.com", "ioc_type": "domain", "source_feed": "test",
             "first_seen": None, "last_seen": None, "confidence": 50, "tags": "[]",
             "malware_family": None, "tlp": "white", "severity": "medium"},
        ]
        df = pd.DataFrame(records)
        features = extract_features(df)
        assert features.iloc[0]["ioc_type_ip"] == 1
        assert features.iloc[0]["ioc_type_domain"] == 0
        assert features.iloc[1]["ioc_type_domain"] == 1

    def test_tlp_numeric(self):
        records = [
            {"ioc_value": "test", "ioc_type": "ip", "source_feed": "test",
             "first_seen": None, "last_seen": None, "confidence": 50, "tags": "[]",
             "malware_family": None, "tlp": "red", "severity": "high"},
        ]
        df = pd.DataFrame(records)
        features = extract_features(df)
        assert features.iloc[0]["tlp_numeric"] == 3

    def test_no_nan_in_output(self):
        records = [
            {"ioc_value": "test", "ioc_type": "ip", "source_feed": "test",
             "first_seen": None, "last_seen": None, "confidence": 50, "tags": None,
             "malware_family": None, "tlp": None, "severity": "medium"},
        ]
        df = pd.DataFrame(records)
        features = extract_features(df)
        assert features.isna().sum().sum() == 0


class TestPredictor:
    def test_no_model_returns_fallback(self):
        predictor = Predictor(model_data=None)
        result = predictor.predict_single({
            "ioc_value": "1.2.3.4",
            "ioc_type": "ip",
            "source_feed": "test",
            "confidence": 50.0,
        })
        assert result["severity"] == "medium"
        assert result["confidence"] == 0.0

    def test_batch_no_model_returns_fallback(self):
        predictor = Predictor(model_data=None)
        results = predictor.predict_batch([
            {"ioc_value": "1.2.3.4", "ioc_type": "ip"},
            {"ioc_value": "evil.com", "ioc_type": "domain"},
        ])
        assert len(results) == 2
        assert all(r["severity"] == "medium" for r in results)

    def test_batch_empty_input(self):
        predictor = Predictor(model_data=None)
        assert predictor.predict_batch([]) == []
