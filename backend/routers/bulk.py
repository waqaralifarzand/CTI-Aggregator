from fastapi import APIRouter
from ..utils.response import ok

router = APIRouter()


@router.post("/bulk/scan")
async def submit_bulk():
    return ok({"status": "not implemented — Phase 7"})


@router.get("/bulk/{job_id}")
async def get_bulk_job(job_id: str):
    return ok({"status": "not implemented — Phase 7"})
