from fastapi import APIRouter
from ..utils.response import ok

router = APIRouter()


@router.get("/ml/metrics")
async def get_ml_metrics():
    return ok({"status": "not implemented — Phase 6"})


@router.post("/ml/train")
async def train_model():
    return ok({"status": "not implemented — Phase 6"})


@router.get("/ml/features")
async def get_feature_importance():
    return ok({"status": "not implemented — Phase 6"})
