from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import settings
from backend.database import init_db
from backend.utils.logging import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CTI Aggregator...")
    init_db()
    logger.info("Database initialized.")

    # Load ML model into app state if it exists
    try:
        import joblib

        model_data = joblib.load(settings.MODEL_PATH)
        app.state.ml_model = model_data
        logger.info(f"ML model loaded: version={model_data.get('version', 'unknown')}")
    except FileNotFoundError:
        app.state.ml_model = None
        logger.info("No ML model found. Prediction endpoint will use fallback.")

    yield
    logger.info("Shutting down CTI Aggregator.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="CTI Aggregator",
        description="Automated Cyber Threat Intelligence Aggregator and Normalization Framework",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Import and register routers
    from backend.routers import feeds, indicators, anomalies, predictions, dashboard

    app.include_router(feeds.router, prefix="/api/v1/feeds", tags=["feeds"])
    app.include_router(indicators.router, prefix="/api/v1/indicators", tags=["indicators"])
    app.include_router(anomalies.router, prefix="/api/v1/anomalies", tags=["anomalies"])
    app.include_router(predictions.router, prefix="/api/v1/predictions", tags=["predictions"])
    app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])

    @app.get("/")
    def root():
        return {"name": "CTI Aggregator", "version": "1.0.0", "status": "running"}

    return app


app = create_app()
