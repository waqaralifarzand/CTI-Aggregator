class TestPredictionsAPI:
    def test_model_info_no_model(self, client):
        response = client.get("/api/v1/predictions/model-info")
        assert response.status_code == 200
        data = response.json()
        assert data["trained"] is False

    def test_classify_no_model_fallback(self, client):
        response = client.post("/api/v1/predictions/classify", json={
            "ioc_value": "1.2.3.4",
            "ioc_type": "ip",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["severity"] == "medium"  # fallback
        assert data["confidence"] == 0.0

    def test_batch_classify_no_model(self, client):
        response = client.post("/api/v1/predictions/batch", json={
            "indicators": [
                {"ioc_value": "1.2.3.4", "ioc_type": "ip"},
                {"ioc_value": "evil.com", "ioc_type": "domain"},
            ]
        })
        assert response.status_code == 200
        assert len(response.json()["predictions"]) == 2
