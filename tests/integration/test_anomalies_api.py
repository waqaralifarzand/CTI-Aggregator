class TestAnomaliesAPI:
    def test_list_anomalies_empty(self, client):
        response = client.get("/api/v1/anomalies")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 0
        assert "items" in data

    def test_anomaly_summary(self, client):
        response = client.get("/api/v1/anomalies/summary")
        assert response.status_code == 200
        data = response.json()
        assert "total_flags" in data
        assert "by_type" in data

    def test_run_detection_with_data(self, client, seed_indicators):
        response = client.post("/api/v1/anomalies/run")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["flags_generated"] >= 0
