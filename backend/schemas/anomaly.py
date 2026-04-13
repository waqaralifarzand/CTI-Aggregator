from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List


class AnomalyFlagRead(BaseModel):
    id: int
    indicator_id: int
    flag_type: str
    description: Optional[str] = None
    anomaly_score: float
    detected_at: Optional[datetime] = None
    metadata_json: Optional[str] = None

    model_config = {"from_attributes": True}


class AnomalyList(BaseModel):
    total: int
    page: int
    per_page: int
    items: List[AnomalyFlagRead]


class AnomalySummary(BaseModel):
    total_flags: int
    by_type: dict


class AnomalyRunResponse(BaseModel):
    status: str
    flags_generated: int
