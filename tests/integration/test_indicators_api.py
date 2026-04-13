class TestIndicatorsAPI:
    def test_list_indicators_empty(self, client):
        response = client.get("/api/v1/indicators")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 0
        assert "items" in data

    def test_list_indicators_with_data(self, client, seed_indicators):
        response = client.get("/api/v1/indicators")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 5
        assert len(data["items"]) >= 5

    def test_list_indicators_filter_by_type(self, client, seed_indicators):
        response = client.get("/api/v1/indicators?ioc_type=ip")
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["ioc_type"] == "ip"

    def test_list_indicators_filter_by_severity(self, client, seed_indicators):
        response = client.get("/api/v1/indicators?severity=critical")
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["severity"] == "critical"

    def test_list_indicators_pagination(self, client, seed_indicators):
        response = client.get("/api/v1/indicators?page=1&per_page=2")
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) == 2
        assert data["page"] == 1
        assert data["per_page"] == 2

    def test_get_indicator_detail(self, client, seed_indicators):
        # First get the list to find an ID
        list_response = client.get("/api/v1/indicators")
        first_id = list_response.json()["items"][0]["id"]

        response = client.get(f"/api/v1/indicators/{first_id}")
        assert response.status_code == 200
        assert response.json()["id"] == first_id

    def test_get_indicator_not_found(self, client):
        response = client.get("/api/v1/indicators/99999")
        assert response.status_code == 404

    def test_search_indicator(self, client, seed_indicators):
        response = client.get("/api/v1/indicators/search?value=185.220.101.45")
        assert response.status_code == 200
        data = response.json()
        assert data["value"] == "185.220.101.45"
        assert len(data["results"]) >= 1

    def test_export_csv(self, client, seed_indicators):
        response = client.get("/api/v1/indicators/export")
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
