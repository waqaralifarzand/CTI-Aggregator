import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.database import Base, get_db
from backend.main import create_app
# Import ALL models so Base.metadata knows about them before create_all
from backend.models.indicator import Indicator
from backend.models.feed_run import FeedRun
from backend.models.anomaly_flag import AnomalyFlag
from backend.models.ml_prediction import MLPrediction
from backend.models.scan_history import ScanHistory


# Use StaticPool so all connections share the same in-memory database
TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = sessionmaker(bind=TEST_ENGINE)

# Create all tables once at module import time
Base.metadata.create_all(TEST_ENGINE)


@pytest.fixture
def db_session():
    session = TestSession()
    yield session
    session.rollback()
    session.close()


@pytest.fixture
def client(db_session):
    app = create_app()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


@pytest.fixture
def seed_indicators(db_session):
    """Seed database with sample indicators for testing."""
    indicators = [
        Indicator(
            ioc_value="185.220.101.45",
            ioc_type="ip",
            source_feed="alienvault_otx",
            severity="high",
            confidence=85.0,
            tags='["botnet", "c2"]',
            malware_family="Emotet",
            tlp="green",
        ),
        Indicator(
            ioc_value="185.220.101.45",
            ioc_type="ip",
            source_feed="urlhaus",
            severity="high",
            confidence=75.0,
            tags='["malware"]',
            malware_family="Emotet",
            tlp="white",
        ),
        Indicator(
            ioc_value="http://malicious.example.com/payload.exe",
            ioc_type="url",
            source_feed="urlhaus",
            severity="high",
            confidence=90.0,
            tags='["exe", "mirai"]',
            malware_family="Mirai",
            tlp="white",
        ),
        Indicator(
            ioc_value="evil-domain.example.com",
            ioc_type="domain",
            source_feed="misp",
            severity="critical",
            confidence=70.0,
            tags='["phishing"]',
            malware_family=None,
            tlp="amber",
        ),
        Indicator(
            ioc_value="a1b2c3d4e5f6" * 5 + "a1b2",
            ioc_type="hash_sha256",
            source_feed="malwarebazaar",
            severity="high",
            confidence=90.0,
            tags='["trojan"]',
            malware_family="AgentTesla",
            tlp="white",
        ),
    ]
    for ind in indicators:
        db_session.add(ind)
    db_session.commit()
    return indicators


# --- Fixture file loaders ---

@pytest.fixture
def sample_urlhaus_response():
    with open("tests/fixtures/urlhaus_recent_sample.json") as f:
        return json.load(f)


@pytest.fixture
def sample_malwarebazaar_response():
    with open("tests/fixtures/malwarebazaar_recent_sample.json") as f:
        return json.load(f)


@pytest.fixture
def sample_otx_response():
    with open("tests/fixtures/otx_pulse_sample.json") as f:
        return json.load(f)


@pytest.fixture
def sample_misp_response():
    with open("tests/fixtures/misp_event_sample.json") as f:
        return json.load(f)
