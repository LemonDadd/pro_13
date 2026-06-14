from typing import Any, Optional
from pydantic import BaseModel, ConfigDict


class BatchMaskRequest(BaseModel):
    strategy: str = "middle"
    format: str = "text"
    include_types: Optional[list[str]] = None


class BatchJobResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    jobId: str
    status: str
    inputSize: Optional[int] = None
    outputSize: Optional[int] = None
    hitCounts: Optional[dict] = None
    errorMessage: Optional[str] = None
    maskedContent: Optional[str] = None
    createdAt: Optional[str] = None
    startedAt: Optional[str] = None
    completedAt: Optional[str] = None
