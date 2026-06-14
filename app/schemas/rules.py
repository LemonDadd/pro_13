from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class CustomRuleRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type_name: str = Field(..., description="规则类型名称")
    pattern: str = Field(..., description="正则表达式")
    description: str = ""
    confidence: str = Field(default="med", pattern="^(high|med|low)$")
    priority: int = Field(default=50, ge=1, le=1000)
    validator: Optional[str] = None
    enabled: bool = True


class CustomRuleResponse(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    type_name: str
    pattern: str
    description: str
    confidence: str
    priority: int
    enabled: bool
    validator: Optional[str] = None


class CustomRuleListResponse(BaseModel):
    rules: list[CustomRuleResponse]
    total: int
