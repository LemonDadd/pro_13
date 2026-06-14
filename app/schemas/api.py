from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict


class DetectRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    text: Optional[str] = None
    json_obj: Optional[Any] = Field(default=None, alias="json")
    include_types: Optional[list[str]] = None


class FindingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type: str
    start: int
    end: int
    length: int
    valueHash: str
    confidence: str
    fieldPath: Optional[str] = None


class DetectResponse(BaseModel):
    findings: list[FindingResponse]
    total: int


class MaskRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    text: Optional[str] = None
    json_obj: Optional[Any] = Field(default=None, alias="json")
    content: Optional[str] = None
    format: str = "text"
    strategy: str = "middle"
    include_types: Optional[list[str]] = None


class MaskResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    maskedText: Optional[str] = None
    maskedJson: Optional[Any] = Field(default=None, alias="json")
    mappingId: str
    findings: list[FindingResponse]
    total: int


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


class DailyStatsResponse(BaseModel):
    date: str
    total_detect: int
    total_mask: int
    type_distribution: dict[str, int]
