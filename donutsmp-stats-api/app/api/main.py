from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging
from app.config import load_config
from app.api.routes import router
from app.main import initialize_app, shutdown_app, state
from app.utils.logging import setup_logging

# Setup logging first
logger = setup_logging()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    settings = load_config()
    app.state.settings = settings
    await initialize_app(settings)
    yield
    # Shutdown
    await shutdown_app()

app = FastAPI(
    title="DonutSMP Stats API",
    description="API for retrieving DonutSMP player statistics via Minecraft bot",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(router)

@app.get("/")
async def root():
    return {"service": "DonutSMP Stats API", "version": "1.0.0", "status": "running"}
