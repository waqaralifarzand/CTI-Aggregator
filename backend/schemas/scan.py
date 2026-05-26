from pydantic import BaseModel, field_validator
from typing import Any, Optional


class ScanRequest(BaseModel):
    value: str

    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("IoC value cannot be empty")
        return v


class IocInfo(BaseModel):
    value: str
    type: str


class GeoData(BaseModel):
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None


class WhoisData(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    name_servers: Optional[list[str]] = None
    status: Optional[str] = None


class BlacklistStatus(BaseModel):
    otx_blacklist: str = "clean"
    urlhaus: str = "clean"
    malwarebazaar: str = "clean"
    virustotal: str = "clean"


class ScanResponse(BaseModel):
    scan_id: str
    ioc: IocInfo
    overall_severity: str
    threat_score: int
    ml_severity: Optional[str] = None
    ml_confidence: Optional[float] = None
    scanned_at: str
    feeds: dict[str, Any]
    blacklist_status: BlacklistStatus
    recommendations: list[str]


class RecentScanItem(BaseModel):
    scan_id: str
    ioc_value: str
    ioc_type: str
    overall_severity: str
    threat_score: int
    scanned_at: str
