from fastapi import APIRouter
from ..utils.response import ok

router = APIRouter()


@router.get("/feeds")
async def get_feeds():
    return ok({"status": "not implemented — Phase 4"})


@router.post("/feeds/{feed_name}/refresh")
async def refresh_feed(feed_name: str):
    return ok({"status": "not implemented — Phase 4"})
