"""FastAPI main application"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from atr.core.db import Base, engine
from atr.api.routes_agents import router as agents_router
from atr.api.routes_verify import router as verify_router
from atr.api.routes_health import router as health_router
from atr.pki.ca import get_ca

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Agent Trust Registry",
    description="Proof-of-concept for agent identity and trust management",
    version="0.1.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(agents_router)
app.include_router(verify_router)
app.include_router(health_router)

# Serve static files (UI)
static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.on_event("startup")
async def startup_event():
    """Initialize CA on startup"""
    get_ca()  # This will create CA if it doesn't exist


@app.get("/")
def root():
    """Root endpoint - serve UI"""
    ui_path = static_dir / "index.html"
    if ui_path.exists():
        return FileResponse(ui_path)
    return {
        "service": "Agent Trust Registry",
        "version": "0.1.0",
        "docs": "/docs",
        "ui": "/static/index.html"
    }
