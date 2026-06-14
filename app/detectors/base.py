import json
from typing import Any

from app.detectors.finding import Finding
from app.rules.engine import Rule, get_rule_engine
from app.utils.hash_utils import compute_value_hash, merge_findings, is_whitelist_field
from app.utils.validators import run_validator
from app.utils.json_traverse import traverse_json, get_field_name
from app.utils.normalize import normalize_text, map_position
from app.detectors.ner import get_detector_pipeline

__all__ = ["Finding"]


def detect_text(text: str, include_types: list[str] | None = None, tenant: str = "default") -> list[Finding]:
    if not text:
        return []

    normalized, pos_map = normalize_text(text)
    if not normalized:
        return []

    engine = get_rule_engine()
    rules = engine.get_rules(tenant=tenant)

    findings = []
    for rule in rules:
        if include_types and rule.type_name not in include_types:
            continue
        if not rule.regex:
            continue
        for match in rule.regex.finditer(normalized):
            norm_start = match.start()
            norm_end = match.end()
            orig_start, orig_end = map_position(norm_start, norm_end, pos_map)
            orig_value = text[orig_start:orig_end]

            confidence = rule.confidence
            if rule.validator and not run_validator(rule.validator, orig_value):
                confidence = _downgrade_confidence(confidence)

            findings.append(
                Finding(
                    type=rule.type_name,
                    start=orig_start,
                    end=orig_end,
                    value=orig_value,
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

    pipeline = get_detector_pipeline()
    extra_findings = pipeline.run_extra_detectors(text, include_types=include_types, tenant=tenant)
    result.extend(extra_findings)

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
