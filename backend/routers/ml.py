from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from database import get_db, SessionLocal
from models.scan_result import ScanResult
from services import ml_service
from ml import trainer
from utils.response import ok, err

router = APIRouter()

MIN_TRAINING_SAMPLES = 50


def _run_training(db_session):
    """Background task: train model then bust the in-process cache."""
    try:
        trainer.train_model(db_session)
        ml_service._bust_cache()
    except Exception:
        pass
    finally:
        db_session.close()


@router.get("/ml/metrics")
def get_ml_metrics():
    """Return the latest training metrics including model_trained flag."""
    return ok(ml_service.get_metrics())


@router.post("/ml/train")
def trigger_training(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Check scan count, then kick off model training as a background task."""
    total_scans = db.query(ScanResult).count()
    if total_scans < MIN_TRAINING_SAMPLES:
        return err(
            f"Insufficient training data. Need at least {MIN_TRAINING_SAMPLES} scans, "
            f"currently have {total_scans}.",
            status_code=400,
        )

    bg_session = SessionLocal()
    background_tasks.add_task(_run_training, bg_session)
    return ok(
        {
            "message": "Model training started.",
            "training_samples": total_scans,
        }
    )


@router.get("/ml/features")
def get_feature_importance():
    """Return feature importances from the trained model, sorted descending."""
    features = ml_service.get_feature_importance()
    if not features:
        return ok({"features": [], "message": "Model not trained yet."})
    return ok(features)
