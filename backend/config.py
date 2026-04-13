from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "sqlite:///./cti_aggregator.db"

    # API Keys
    OTX_API_KEY: str = ""
    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = True

    # App
    CORS_ORIGINS: List[str] = ["http://localhost:5173"]
    LOG_LEVEL: str = "INFO"

    # ML
    MODEL_PATH: str = "backend/ml/models/rf_severity_model.joblib"
    RF_N_ESTIMATORS: int = 200
    RF_MAX_DEPTH: int = 15

    # Rate limits (requests per minute)
    OTX_RATE_LIMIT: int = 30
    URLHAUS_RATE_LIMIT: int = 60
    MALWAREBAZAAR_RATE_LIMIT: int = 60
    MISP_RATE_LIMIT: int = 30

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
