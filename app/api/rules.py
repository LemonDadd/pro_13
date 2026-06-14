import re

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.auth import get_tenant_id
from app.rules.engine import get_rule_engine
from app.schemas.api import (
    CustomRuleRequest,
    CustomRuleResponse,
    CustomRuleListResponse,
)

router = APIRouter(prefix="/rules", tags=["rules"])

BUILTIN_RULE_TYPES = {
    "PHONE_CN", "ID_CARD", "EMAIL", "BANK_CARD",
    "AWS_KEY", "AWS_SECRET", "JWT", "IP_PRIVATE",
    "CHINA_POSTCODE", "PASSPORT_CN",
}


@router.get("/builtin", response_model=CustomRuleListResponse)
def list_builtin_rules(
    tenant_id: str = Depends(get_tenant_id),
):
    engine = get_rule_engine()
    rules = [r for r in engine.get_rules(tenant="default") if r.tenant == "default"]
    return CustomRuleListResponse(
        rules=[
            CustomRuleResponse(
                type_name=r.type_name,
                pattern=r.pattern,
                description=r.description,
                confidence=r.confidence,
                priority=r.priority,
                validator=r.validator,
                enabled=r.enabled,
            )
            for r in rules
        ],
        total=len(rules),
    )


@router.get("/custom", response_model=CustomRuleListResponse)
def list_custom_rules(
    tenant_id: str = Depends(get_tenant_id),
):
    engine = get_rule_engine()
    all_rules = engine.get_rules(tenant=tenant_id)
    custom_rules = [r for r in all_rules if r.tenant == tenant_id and tenant_id != "default"]

    if tenant_id == "default":
        custom_rules = [r for r in all_rules if r.tenant == "default" and r.type_name not in BUILTIN_RULE_TYPES]

    return CustomRuleListResponse(
        rules=[
            CustomRuleResponse(
                type_name=r.type_name,
                pattern=r.pattern,
                description=r.description,
                confidence=r.confidence,
                priority=r.priority,
                validator=r.validator,
                enabled=r.enabled,
            )
            for r in custom_rules
        ],
        total=len(custom_rules),
    )


@router.post("/custom", response_model=CustomRuleResponse, status_code=201)
def add_custom_rule(
    request: CustomRuleRequest,
    tenant_id: str = Depends(get_tenant_id),
):
    if request.type_name in BUILTIN_RULE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot override builtin rule type: {request.type_name}",
        )

    try:
        re.compile(request.pattern)
    except re.error as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid regex pattern: {str(e)}",
        )

    validators = {"id_card", "luhn"}
    if request.validator and request.validator.lower() not in validators:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid validator. Available: {', '.join(validators)}",
        )

    engine = get_rule_engine()
    config = {
        "description": request.description,
        "pattern": request.pattern,
        "confidence": request.confidence,
        "priority": request.priority,
        "validator": request.validator,
        "enabled": request.enabled,
    }
    engine.add_custom_rule(request.type_name, config, tenant=tenant_id)

    return CustomRuleResponse(
        type_name=request.type_name,
        pattern=request.pattern,
        description=request.description,
        confidence=request.confidence,
        priority=request.priority,
        validator=request.validator,
        enabled=request.enabled,
    )


@router.delete("/custom/{type_name}", status_code=204)
def delete_custom_rule(
    type_name: str,
    tenant_id: str = Depends(get_tenant_id),
):
    if type_name in BUILTIN_RULE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete builtin rule type: {type_name}",
        )

    engine = get_rule_engine()
    engine.remove_custom_rule(type_name, tenant=tenant_id)
    return None
