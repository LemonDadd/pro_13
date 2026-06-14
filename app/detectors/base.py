import json
from typing import Any

from app.rules.engine import Rule, get_rule_engine
from app.utils.hash_utils import compute_value_hash, merge_findings, is_whitelist_field
from app.utils.validators import run_validator
from app.utils.json_traverse import traverse_json, get_field_name


class Finding:
    def __init__(
        self,
        type: str,
        start: int,
        end: int,
        value: str,
        confidence: str = "med",
        field_path: str | None = None,
        is_whitelist: bool = False,
    ):
        self.type = type
        self.start = start
        self.end = end
        self.length = end - start
        self.value = value
        self.value_hash = compute_value_hash(value)
        self.confidence = confidence
        self.field_path = field_path
        self.is_whitelist = is_whitelist

    def to_dict(self, include_value: bool = False) -> dict:
        d = {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "valueHash": self.value_hash,
            "confidence": self.confidence,
        }
        if self.field_path:
            d["fieldPath"] = self.field_path
        if include_value:
            d["value"] = self.value
        return d


def detect_text(text: str, include_types: list[str] | None = None, tenant: str = "default") -> list[Finding]:
    if not text:
        return []
    engine = get_rule_engine()
    rules = engine.get_rules(tenant=tenant)
    whitelist = engine.get_whitelist_fields()

    findings = []
    for rule in rules:
        if include_types and rule.type_name not in include_types:
            continue
        if not rule.regex:
            continue
        for match in rule.regex.finditer(text):
            value = match.group(0)
            start = match.start()
            end = match.end()
            confidence = rule.confidence
            if rule.validator and not run_validator(rule.validator, value):
                confidence = _downgrade_confidence(confidence)
            findings.append(
                Finding(
                    type=rule.type_name,
                    start=start,
                    end=end,
                    value=value,
                    confidence=confidence,
                )
            )

    merged = merge_findings([f.to_dict(include_value=True) for f in findings])
    result = []
    for fd in merged:
        result.append(
            Finding(
                type=fd["type"],
                start=fd["start"],
                end=fd["end"],
                value=fd["value"],
                confidence=fd.get("confidence", "med"),
            )
        )
    return result


def detect_json(obj: Any, include_types: list[str] | None = None, tenant: str = "default") -> list[Finding]:
    engine = get_rule_engine()
    whitelist = engine.get_whitelist_fields()
    all_findings = []

    for path, value in traverse_json(obj):
        if not isinstance(value, str) or not value:
            continue
        field_name = get_field_name(path)
        text_findings = detect_text(value, include_types=include_types, tenant=tenant)
        for f in text_findings:
            f.field_path = path
            if field_name and is_whitelist_field(field_name, whitelist):
                f.is_whitelist = True
            all_findings.append(f)

    return all_findings


def _downgrade_confidence(confidence: str) -> str:
    if confidence == "high":
        return "med"
    if confidence == "med":
        return "low"
    return "low"


def normalize_text(text: str) -> str:
    return text
