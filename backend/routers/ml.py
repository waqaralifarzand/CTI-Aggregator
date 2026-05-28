from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from database import get_db
from services import ml_service
from ml import trainer
from utils.response import ok, err

router = APIRouter()


def _run_training(db_session):
    """Background task wrapper for model training."""
    try:
        trainer.train_model(db_session)
    except Exception:
        pass
    finally:
        db_session.close()


@router.get("/ml/metrics")
def get_ml_metrics():
    """Return the latest training metrics."""
    metrics = ml_service.get_metrics()
    if metrics is None:
        return ok(None)
    return ok(metrics)


@router.post("/ml/train")
def trigger_training(
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Kick off model training as a background task."""
    # Detach the session so the background thread gets its own connection
    from database import SessionLocal
    bg_session = SessionLocal()
    background_tasks.add_task(_run_training, bg_session)
    return ok(
        {
            "message": "Model training started in the background.",
            "status": "pending",
        }
    )


@router.get("/ml/features")
def get_feature_importance():
    """Return feature importances from the trained model."""
    features = ml_service.get_feature_importance()
    return ok(features)
