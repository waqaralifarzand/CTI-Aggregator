from fastapi import APIRouter
from ..utils.response import ok

router = APIRouter()


@router.post("/scan")
async def submit_scan():
    return ok({"status": "not implemented — Phase 2"})


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str):
    return ok({"status": "not implemented — Phase 2"})


@router.get("/scans/recent")
async def recent_scans():
    return ok({"status": "not implemented — Phase 2"})
