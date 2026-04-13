import json

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from backend.database import get_db
from backend.models.scan_history import ScanHistory
from backend.schemas.prediction import (
    PredictRequest, PredictResponse, BatchPredictRequest, BatchPredictResponse,
    TrainRequest, TrainResponse, ModelInfoResponse,
)
from backend.ml.predict import Predictor
from backend.ml.training import train_model
from backend.models.indicator import Indicator

router = APIRouter()


def get_predictor(request: Request) -> Predictor:
    """Get or create a Predictor instance, using app state for the model."""
    return Predictor(model_data=getattr(request.app.state, "ml_model", None))


@router.post("/classify", response_model=PredictResponse)
def classify_indicator(body: PredictRequest, predictor: Predictor = Depends(get_predictor)):
    """Classify a single IoC's severity using the ML model."""
    result = predictor.predict_single(body.model_dump())
    return PredictResponse(severity=result["severity"], confidence=result["confidence"])


@router.post("/batch", response_model=BatchPredictResponse)
def classify_batch(body: BatchPredictRequest, predictor: Predictor = Depends(get_predictor)):
    """Classify multiple IoCs in one request."""
    records = [ind.model_dump() for ind in body.indicators]
    results = predictor.predict_batch(records)
    return BatchPredictResponse(predictions=results)


@router.post("/train", response_model=TrainResponse)
def trigger_training(
    body: TrainRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Train/retrain the ML model on current indicator data."""
    indicators = db.query(Indicator).all()
    if len(indicators) < 10:
        return TrainResponse(
            status="failed",
            version=body.version,
            metrics={"error": "Not enough data. Need at least 10 indicators."},
        )

    # Convert to dicts
    records = []
    for ind in indicators:
        records.append({
            "ioc_value": ind.ioc_value,
            "ioc_type": ind.ioc_type,
            "source_feed": ind.source_feed,
            "first_seen": ind.first_seen,
            "last_seen": ind.last_seen,
            "severity": ind.severity,
            "confidence": ind.confidence,
            "tags": ind.tags,
            "malware_family": ind.malware_family,
            "tlp": ind.tlp,
        })

    metrics = train_model(records, model_version=body.version)

    # Reload model into app state
    import joblib
    from backend.config import settings

    try:
        request.app.state.ml_model = joblib.load(settings.MODEL_PATH)
    except FileNotFoundError:
        pass

    # Log to scan history
    scan = ScanHistory(
        action="train",
        details=json.dumps({"version": body.version, "status": "completed"}),
    )
    db.add(scan)
    db.commit()

    return TrainResponse(status="completed", version=body.version, metrics=metrics)


@router.get("/model-info", response_model=ModelInfoResponse)
def get_model_info(request: Request):
    """Get current model metadata."""
    model_data = getattr(request.app.state, "ml_model", None)
    if model_data is None:
        return ModelInfoResponse(trained=False)

    return ModelInfoResponse(
        version=model_data.get("version"),
        trained=True,
        feature_importances=model_data.get("feature_importances"),
        classification_report=model_data.get("classification_report"),
    )
