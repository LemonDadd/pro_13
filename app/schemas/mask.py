from typing import Any, Optional
from pydantic import BaseModel, Field, ConfigDict

from app.schemas.common import FindingResponse


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
