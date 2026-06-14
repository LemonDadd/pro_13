import os
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Form
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_id
from app.core.config import settings
from app.core.database import get_db
from app.models.batch import BatchJob
from app.schemas.api import BatchJobResponse

router = APIRouter(prefix="/batch", tags=["batch"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@router.post("/mask", response_model=BatchJobResponse)
async def batch_mask(
    file: UploadFile = File(...),
    strategy: str = Form("middle"),
    format: str = Form("text"),
    include_types: str = Form(None),
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    if strategy not in ("middle", "hash", "remove"):
        raise HTTPException(status_code=400, detail="Invalid strategy")

    content = await file.read()
    size_mb = len(content) / (1024 * 1024)
    if size_mb > settings.batch_max_size_mb:
        raise HTTPException(status_code=413, detail=f"File too large. Max {settings.batch_max_size_mb}MB")

    job_id = str(uuid.uuid4())
    input_path = os.path.join("data", "batch", f"{job_id}_input.txt")
    os.makedirs(os.path.dirname(input_path), exist_ok=True)

    with open(input_path, "wb") as f:
        f.write(content)

    types_list = None
    if include_types:
        types_list = [t.strip() for t in include_types.split(",") if t.strip()]

    job = BatchJob(
        id=job_id,
        tenant_id=tenant_id,
        status="pending",
        format=format,
        strategy=strategy,
        include_types=types_list,
        input_size=len(content),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    return _job_to_response(job)


@router.get("/{job_id}", response_model=BatchJobResponse)
def get_batch_status(
    job_id: str,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    job = db.query(BatchJob).filter(BatchJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return _job_to_response(job, include_content=True)


def _job_to_response(job: BatchJob, include_content: bool = False) -> BatchJobResponse:
    masked_content = None
    if include_content and job.status == "completed" and job.output_path:
        if os.path.exists(job.output_path):
            try:
                with open(job.output_path, "r", encoding="utf-8") as f:
                    masked_content = f.read()
            except Exception:
                masked_content = None

    return BatchJobResponse(
        jobId=job.id,
        status=job.status,
        inputSize=job.input_size,
        outputSize=job.output_size,
        hitCounts=job.hit_counts,
        errorMessage=job.error_message,
        maskedContent=masked_content,
        createdAt=job.created_at.isoformat() if job.created_at else None,
        startedAt=job.started_at.isoformat() if job.started_at else None,
        completedAt=job.completed_at.isoformat() if job.completed_at else None,
    )
