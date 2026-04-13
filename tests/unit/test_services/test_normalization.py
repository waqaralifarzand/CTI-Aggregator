import json

from backend.services.normalization import normalize_batch, validate_record, serialize_tags


class TestValidateRecord:
    def test_valid_record(self):
        record = {"ioc_value": "1.2.3.4", "ioc_type": "ip", "severity": "high", "tlp": "white"}
        assert validate_record(record) is True

    def test_missing_ioc_value(self):
        record = {"ioc_value": "", "ioc_type": "ip"}
        assert validate_record(record) is False

    def test_invalid_ioc_type(self):
        record = {"ioc_value": "1.2.3.4", "ioc_type": "invalid_type"}
        assert validate_record(record) is False

    def test_invalid_severity_gets_defaulted(self):
        record = {"ioc_value": "1.2.3.4", "ioc_type": "ip", "severity": "unknown"}
        assert validate_record(record) is True
        assert record["severity"] == "medium"

    def test_invalid_tlp_gets_defaulted(self):
        record = {"ioc_value": "1.2.3.4", "ioc_type": "ip", "severity": "high", "tlp": "purple"}
        assert validate_record(record) is True
        assert record["tlp"] == "white"


class TestSerializeTags:
    def test_list_tags(self):
        record = {"tags": ["a", "b"]}
        result = serialize_tags(record)
        assert result["tags"] == '["a", "b"]'

    def test_none_tags(self):
        record = {"tags": None}
        result = serialize_tags(record)
        assert result["tags"] == "[]"


class TestNormalizeBatch:
    def test_valid_batch(self):
        records = [
            {
                "ioc_value": "1.2.3.4",
                "ioc_type": "ip",
                "source_feed": "urlhaus",
                "severity": "high",
                "confidence": 85.0,
                "tags": ["test"],
                "tlp": "white",
                "first_seen": "2026-03-20T12:00:00",
                "last_seen": None,
            }
        ]
        df = normalize_batch(records)
        assert len(df) == 1
        assert df.iloc[0]["ioc_value"] == "1.2.3.4"
        assert df.iloc[0]["ioc_type"] == "ip"

    def test_filters_invalid(self):
        records = [
            {"ioc_value": "", "ioc_type": "ip"},
            {"ioc_value": "1.2.3.4", "ioc_type": "ip", "severity": "high", "confidence": 50.0, "tags": [], "tlp": "white"},
        ]
        df = normalize_batch(records)
        assert len(df) == 1

    def test_empty_input(self):
        df = normalize_batch([])
        assert df.empty

    def test_confidence_clamping(self):
        records = [
            {"ioc_value": "1.2.3.4", "ioc_type": "ip", "confidence": 150.0, "severity": "high", "tags": [], "tlp": "white"},
        ]
        df = normalize_batch(records)
        assert df.iloc[0]["confidence"] == 100.0
