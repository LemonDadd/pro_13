from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class FindingResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type: str
    start: int
    end: int
    length: int
    valueHash: str
    confidence: str
    fieldPath: Optional[str] = None
