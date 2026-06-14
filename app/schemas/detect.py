from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict

from app.schemas.common import FindingResponse


class DetectRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    text: Optional[str] = None
    json_obj: Optional[Any] = Field(default=None, alias="json")
    include_types: Optional[list[str]] = None


class DetectResponse(BaseModel):
    findings: list[FindingResponse]
    total: int
