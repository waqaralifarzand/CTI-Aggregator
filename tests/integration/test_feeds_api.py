class TestFeedsAPI:
    def test_get_feed_status(self, client):
        response = client.get("/api/v1/feeds/status")
        assert response.status_code == 200
        data = response.json()
        assert "feeds" in data
        feed_names = [f["feed"] for f in data["feeds"]]
        assert "urlhaus" in feed_names
        assert "malwarebazaar" in feed_names

    def test_get_single_feed_status(self, client):
        response = client.get("/api/v1/feeds/status/urlhaus")
        assert response.status_code == 200
        assert response.json()["feed"] == "urlhaus"

    def test_get_unknown_feed_status(self, client):
        response = client.get("/api/v1/feeds/status/nonexistent")
        assert response.status_code == 404

    def test_fetch_unknown_feed(self, client):
        response = client.post("/api/v1/feeds/fetch", json={"feed": "nonexistent"})
        assert response.status_code == 400

    def test_get_feed_history(self, client):
        response = client.get("/api/v1/feeds/history")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
