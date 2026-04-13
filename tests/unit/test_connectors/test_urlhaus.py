from backend.connectors.urlhaus import URLhausConnector


class TestURLhausConnector:
    def setup_method(self):
        self.connector = URLhausConnector()

    def test_feed_name(self):
        assert self.connector.feed_name == "urlhaus"

    def test_parse_extracts_urls(self, sample_urlhaus_response):
        parsed = self.connector.parse(sample_urlhaus_response["urls"])
        assert len(parsed) == 2
        assert parsed[0]["url"] == "http://malicious-example.com/payload.exe"
        assert parsed[0]["url_status"] == "online"
        assert parsed[1]["url_status"] == "offline"

    def test_normalize_maps_fields(self, sample_urlhaus_response):
        parsed = self.connector.parse(sample_urlhaus_response["urls"])
        normalized = self.connector.normalize(parsed)

        # First URL + 2 hash indicators from payload
        assert len(normalized) >= 3

        # Check URL indicator
        url_ind = normalized[0]
        assert url_ind["ioc_value"] == "http://malicious-example.com/payload.exe"
        assert url_ind["ioc_type"] == "url"
        assert url_ind["source_feed"] == "urlhaus"
        assert url_ind["severity"] == "high"  # online -> high
        assert url_ind["tlp"] == "white"
        assert url_ind["confidence"] == 75.0  # 50 + 25 (spamhaus listed)

    def test_normalize_offline_severity(self, sample_urlhaus_response):
        parsed = self.connector.parse(sample_urlhaus_response["urls"])
        normalized = self.connector.normalize(parsed)

        # Find the offline URL (phishing-site)
        offline = [n for n in normalized if "phishing-site" in n["ioc_value"]]
        assert len(offline) == 1
        assert offline[0]["severity"] == "medium"  # offline -> medium

    def test_normalize_emits_hash_indicators(self, sample_urlhaus_response):
        parsed = self.connector.parse(sample_urlhaus_response["urls"])
        normalized = self.connector.normalize(parsed)

        hashes = [n for n in normalized if n["ioc_type"].startswith("hash_")]
        assert len(hashes) == 2  # sha256 + md5 from first URL's payload

    def test_normalize_empty_input(self):
        result = self.connector.normalize([])
        assert result == []

    def test_parse_empty_input(self):
        result = self.connector.parse([])
        assert result == []
