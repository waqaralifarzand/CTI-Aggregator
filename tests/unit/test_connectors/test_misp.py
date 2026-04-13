from backend.connectors.misp import MISPConnector


class TestMISPConnector:
    def setup_method(self):
        self.connector = MISPConnector()

    def test_feed_name(self):
        assert self.connector.feed_name == "misp"

    def test_parse_flattens_events(self, sample_misp_response):
        parsed = self.connector.parse(sample_misp_response["response"])
        # 1 event with 3 attributes
        assert len(parsed) == 3
        assert parsed[0]["attr_value"] == "phish-domain.example.com"
        assert parsed[0]["attr_type"] == "domain"
        assert parsed[0]["threat_level_id"] == "1"

    def test_normalize_maps_types(self, sample_misp_response):
        parsed = self.connector.parse(sample_misp_response["response"])
        normalized = self.connector.normalize(parsed)
        assert len(normalized) == 3

        types = {n["ioc_type"] for n in normalized}
        assert "domain" in types
        assert "ip" in types
        assert "hash_sha256" in types

    def test_normalize_severity_from_threat_level(self, sample_misp_response):
        parsed = self.connector.parse(sample_misp_response["response"])
        normalized = self.connector.normalize(parsed)
        # threat_level_id=1 -> critical
        for n in normalized:
            assert n["severity"] == "critical"

    def test_normalize_confidence_from_to_ids_and_analysis(self, sample_misp_response):
        parsed = self.connector.parse(sample_misp_response["response"])
        normalized = self.connector.normalize(parsed)
        # All attributes have to_ids=True, analysis=2
        # confidence = 40 + 30 (to_ids) + 30 (analysis*15=2*15) = 100
        for n in normalized:
            assert n["confidence"] == 100.0

    def test_normalize_tlp_from_tags(self, sample_misp_response):
        parsed = self.connector.parse(sample_misp_response["response"])
        normalized = self.connector.normalize(parsed)
        for n in normalized:
            assert n["tlp"] == "amber"

    def test_normalize_malware_family_from_galaxy(self, sample_misp_response):
        parsed = self.connector.parse(sample_misp_response["response"])
        normalized = self.connector.normalize(parsed)
        # Tags include misp-galaxy:malware="Dridex"
        for n in normalized:
            assert n["malware_family"] == "Dridex"

    def test_normalize_empty_input(self):
        assert self.connector.normalize([]) == []
