from storage.romeo_db import RomeoDB as DBConnection
from fastapi import APIRouter, Depends
from panel.config import require_auth

router = APIRouter()


@router.get("/api/stats")
def stats(user: str = Depends(require_auth)):
    with RomeoDB() as db:
        return db.get_stats()

@router.get("/api/detailed-stats")
def detailed_stats(user: str = Depends(require_auth)):
    with RomeoDB() as db:
        return db.get_detailed_stats()

@router.get("/api/chart")
def chart(user: str = Depends(require_auth)):
    with RomeoDB() as db:
        return db.get_chart_data()
