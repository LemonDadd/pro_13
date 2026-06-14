import re

from fastapi import HTTPException

from app.rules.engine import Rule, get_rule_engine
from app.schemas.rules import CustomRuleRequest, CustomRuleResponse, CustomRuleListResponse


BUILTIN_RULE_TYPES = {
    "PHONE_CN", "ID_CARD", "EMAIL", "BANK_CARD",
    "AWS_KEY", "AWS_SECRET", "JWT", "IP_PRIVATE",
    "CHINA_POSTCODE", "PASSPORT_CN",
}

VALIDATORS = {"id_card", "luhn"}


def _rule_to_response(rule: Rule) -> CustomRuleResponse:
    return CustomRuleResponse(
        type_name=rule.type_name,
        pattern=rule.pattern,
        description=rule.description,
        confidence=rule.confidence,
        priority=rule.priority,
        validator=rule.validator,
        enabled=rule.enabled,
    )


def list_builtin_rules(tenant_id: str) -> CustomRuleListResponse:
    engine = get_rule_engine()
    rules = [r for r in engine.get_rules(tenant="default") if r.tenant == "default"]
    return CustomRuleListResponse(
        rules=[_rule_to_response(r) for r in rules],
        total=len(rules),
    )


def list_custom_rules(tenant_id: str) -> CustomRuleListResponse:
    engine = get_rule_engine()
    all_rules = engine.get_rules(tenant=tenant_id)

    if tenant_id == "default":
        custom_rules = [r for r in all_rules if r.tenant == "default" and r.type_name not in BUILTIN_RULE_TYPES]
    else:
        custom_rules = [r for r in all_rules if r.tenant == tenant_id]

    return CustomRuleListResponse(
        rules=[_rule_to_response(r) for r in custom_rules],
        total=len(custom_rules),
    )


def add_custom_rule(request: CustomRuleRequest, tenant_id: str) -> CustomRuleResponse:
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

    if request.validator and request.validator.lower() not in VALIDATORS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid validator. Available: {', '.join(VALIDATORS)}",
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
    return _rule_to_response_from_request(request)


def _rule_to_response_from_request(r: CustomRuleRequest) -> CustomRuleResponse:
    return CustomRuleResponse(
        type_name=r.type_name,
        pattern=r.pattern,
        description=r.description,
        confidence=r.confidence,
        priority=r.priority,
        validator=r.validator,
        enabled=r.enabled,
    )


def delete_custom_rule(type_name: str, tenant_id: str):
    if type_name in BUILTIN_RULE_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete builtin rule type: {type_name}",
        )
    engine = get_rule_engine()
    engine.remove_custom_rule(type_name, tenant=tenant_id)
