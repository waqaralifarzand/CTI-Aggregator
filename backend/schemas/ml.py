from typing import List, Optional, Dict, Any
from pydantic import BaseModel


class FeatureImportance(BaseModel):
    feature: str
    importance: float


class MLMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    num_samples: int
    num_classes: int
    class_labels: List[str]
    trained_at: Optional[str] = None
    feature_importances: Optional[List[FeatureImportance]] = None


class TrainResponse(BaseModel):
    message: str
    status: str
