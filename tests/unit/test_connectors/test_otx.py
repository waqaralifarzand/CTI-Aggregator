from backend.connectors.alienvault_otx import AlienVaultOTXConnector


class TestAlienVaultOTXConnector:
    def setup_method(self):
        self.connector = AlienVaultOTXConnector()

    def test_feed_name(self):
        assert self.connector.feed_name == "alienvault_otx"

    def test_parse_flattens_pulses(self, sample_otx_response):
        parsed = self.connector.parse(sample_otx_response["results"])
        # 1 pulse with 3 indicators
        assert len(parsed) == 3
        assert parsed[0]["indicator_value"] == "185.220.101.45"
        assert parsed[0]["indicator_type"] == "IPv4"
        assert parsed[0]["pulse_tags"] == ["botnet", "c2", "tor"]

    def test_normalize_maps_types(self, sample_otx_response):
        parsed = self.connector.parse(sample_otx_response["results"])
        normalized = self.connector.normalize(parsed)
        assert len(normalized) == 3

        types = [n["ioc_type"] for n in normalized]
        assert "ip" in types
        assert "domain" in types
        assert "hash_sha256" in types

    def test_normalize_severity_from_active(self, sample_otx_response):
        parsed = self.connector.parse(sample_otx_response["results"])
        normalized = self.connector.normalize(parsed)

        ip_ind = [n for n in normalized if n["ioc_type"] == "ip"][0]
        assert ip_ind["severity"] == "high"  # is_active=True + malware_family

        hash_ind = [n for n in normalized if n["ioc_type"] == "hash_sha256"][0]
        assert hash_ind["severity"] == "low"  # is_active=False

    def test_normalize_tlp(self, sample_otx_response):
        parsed = self.connector.parse(sample_otx_response["results"])
        normalized = self.connector.normalize(parsed)
        for n in normalized:
            assert n["tlp"] == "green"

    def test_normalize_confidence_scoring(self, sample_otx_response):
        parsed = self.connector.parse(sample_otx_response["results"])
        normalized = self.connector.normalize(parsed)

        ip_ind = [n for n in normalized if n["ioc_type"] == "ip"][0]
        # 60 base + 20 (active) + 10 (malware) = 90
        assert ip_ind["confidence"] == 90.0

    def test_normalize_empty_input(self):
        assert self.connector.normalize([]) == []
