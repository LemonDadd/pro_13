from fastapi import APIRouter, Depends

from app.core.auth import get_tenant_id
from app.schemas.api import (
    CustomRuleRequest,
    CustomRuleResponse,
    CustomRuleListResponse,
)
from app.services import rules_service

router = APIRouter(prefix="/rules", tags=["rules"])


@router.get("/builtin", response_model=CustomRuleListResponse)
def list_builtin_rules(tenant_id: str = Depends(get_tenant_id)):
    return rules_service.list_builtin_rules(tenant_id)


@router.get("/custom", response_model=CustomRuleListResponse)
def list_custom_rules(tenant_id: str = Depends(get_tenant_id)):
    return rules_service.list_custom_rules(tenant_id)


@router.post("/custom", response_model=CustomRuleResponse, status_code=201)
def add_custom_rule(
    request: CustomRuleRequest,
    tenant_id: str = Depends(get_tenant_id),
):
    return rules_service.add_custom_rule(request, tenant_id)


@router.delete("/custom/{type_name}", status_code=204)
def delete_custom_rule(
    type_name: str,
    tenant_id: str = Depends(get_tenant_id),
):
    rules_service.delete_custom_rule(type_name, tenant_id)
    return None
