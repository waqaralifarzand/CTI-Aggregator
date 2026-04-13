from pydantic import BaseModel
from typing import Optional, List, Dict


class PredictRequest(BaseModel):
    ioc_value: str
    ioc_type: str
    source_feed: str = "manual"
    confidence: float = 50.0
    tags: Optional[List[str]] = None
    malware_family: Optional[str] = None


class PredictResponse(BaseModel):
    severity: str
    confidence: float


class BatchPredictRequest(BaseModel):
    indicators: List[PredictRequest]


class BatchPredictResponse(BaseModel):
    predictions: List[dict]


class TrainRequest(BaseModel):
    version: str = "v1"


class TrainResponse(BaseModel):
    status: str
    version: str
    metrics: dict


class ModelInfoResponse(BaseModel):
    version: Optional[str] = None
    trained: bool = False
    feature_importances: Optional[Dict[str, float]] = None
    classification_report: Optional[dict] = None
