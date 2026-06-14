from datetime import datetime

from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_id
from app.core.database import get_db
from app.schemas.api import DailyStatsResponse
from app.services.audit_service import get_daily_stats

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("/daily", response_model=DailyStatsResponse)
def get_daily(
    date: str = Query(None, description="Date in YYYY-MM-DD format, defaults to today"),
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    if date:
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    else:
        target_date = None

    stats = get_daily_stats(db, tenant_id, target_date)
    return DailyStatsResponse(**stats)
