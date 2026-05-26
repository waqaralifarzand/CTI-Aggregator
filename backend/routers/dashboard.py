from fastapi import APIRouter
from ..utils.response import ok

router = APIRouter()


@router.get("/dashboard/stats")
async def get_dashboard_stats():
    return ok({"status": "not implemented — Phase 4"})


@router.get("/dashboard/activity")
async def get_dashboard_activity():
    return ok({"status": "not implemented — Phase 4"})


@router.get("/dashboard/severity-breakdown")
async def get_severity_breakdown():
    return ok({"status": "not implemented — Phase 4"})


@router.get("/dashboard/ioc-breakdown")
async def get_ioc_breakdown():
    return ok({"status": "not implemented — Phase 4"})


@router.get("/dashboard/ticker")
async def get_ticker():
    return ok({"status": "not implemented — Phase 4"})
