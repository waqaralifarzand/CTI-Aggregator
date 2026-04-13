from backend.models.indicator import Indicator


class TestIndicatorModel:
    def test_create_indicator(self, db_session):
        indicator = Indicator(
            ioc_value="192.168.1.1",
            ioc_type="ip",
            source_feed="test",
            severity="medium",
            confidence=50.0,
            tlp="white",
        )
        db_session.add(indicator)
        db_session.commit()
        db_session.refresh(indicator)

        assert indicator.id is not None
        assert indicator.ioc_value == "192.168.1.1"
        assert indicator.ioc_type == "ip"
        assert indicator.severity == "medium"

    def test_default_values(self, db_session):
        indicator = Indicator(
            ioc_value="test.com",
            ioc_type="domain",
            source_feed="test",
        )
        db_session.add(indicator)
        db_session.commit()
        db_session.refresh(indicator)

        assert indicator.severity == "medium"
        assert indicator.confidence == 50.0
        assert indicator.tlp == "white"
