from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import os

load_dotenv()

from .database import create_tables
from .models import *  # ensure all models are registered
from .routers import scan, bulk, feeds, reports, ml, dashboard

app = FastAPI(title="CTI Aggregator API", version="1.0.0")

origins = os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    create_tables()


@app.get("/api/health")
async def health():
    from .utils.response import ok
    return ok({"status": "ok", "db": "connected"})


app.include_router(scan.router, prefix="/api")
app.include_router(bulk.router, prefix="/api")
app.include_router(feeds.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(ml.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
