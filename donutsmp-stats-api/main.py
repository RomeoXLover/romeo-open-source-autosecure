#!/usr/bin/env python3
"""Main entry point for DonutSMP Stats API."""
import uvicorn
from app.config import load_config

if __name__ == "__main__":
    settings = load_config()
    uvicorn.run(
        "app.api.main:app",
        host=settings.api.host,
        port=settings.api.port,
        log_level="info"
    )
