from fastapi import APIRouter
from ..utils.response import ok

router = APIRouter()


@router.get("/reports")
async def get_reports():
    return ok({"status": "not implemented — Phase 5"})


@router.get("/reports/export")
async def export_reports():
    return ok({"status": "not implemented — Phase 5"})
