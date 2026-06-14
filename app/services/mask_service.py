import json
import uuid
from typing import Any

from app.detectors.base import detect_text, detect_json
from app.detectors.finding import Finding
from app.utils.hash_utils import compute_value_hash


MASK_MIDDLE_RULES = {
    "PHONE_CN": (3, 4),
    "ID_CARD": (3, 4),
    "BANK_CARD": (4, 4),
    "EMAIL": (2, 0),
    "default": (1, 1),
}


def mask_value(value: str, strategy: str, type_name: str) -> str:
    if strategy == "remove":
        return ""
    if strategy == "hash":
        return _hash_mask(value)
    if strategy == "middle":
        return _middle_mask(value, type_name)
    return value


def _middle_mask(value: str, type_name: str) -> str:
    if not value:
        return value
    rule = MASK_MIDDLE_RULES.get(type_name, MASK_MIDDLE_RULES["default"])
    keep_left, keep_right = rule

    if type_name == "EMAIL":
        at_idx = value.find("@")
        if at_idx > 0:
            local = value[:at_idx]
            domain = value[at_idx:]
            if len(local) <= keep_left:
                return "*" * len(local) + domain
            masked_local = local[:keep_left] + "*" * max(1, len(local) - keep_left)
            return masked_local + domain
        return value

    length = len(value)
    if length <= keep_left + keep_right:
        return "*" * length
    return value[:keep_left] + "*" * (length - keep_left - keep_right) + value[-keep_right:] if keep_right > 0 else value[:keep_left] + "*" * (length - keep_left)


def _hash_mask(value: str) -> str:
    h = compute_value_hash(value)
    return f"[HASH:{h}]"


def mask_text(
    text: str,
    strategy: str = "middle",
    include_types: list[str] | None = None,
    tenant: str = "default",
) -> tuple[str, list[Finding], str]:
    findings = detect_text(text, include_types=include_types, tenant=tenant)
    mapping_id = str(uuid.uuid4())

    if not findings:
        return text, [], mapping_id

    sorted_findings = sorted(findings, key=lambda f: f.start, reverse=True)

    result = text
    for f in sorted_findings:
        masked = mask_value(f.value, strategy, f.type)
        result = result[:f.start] + masked + result[f.end:]

    return result, findings, mapping_id


def mask_json(
    obj: Any,
    strategy: str = "middle",
    include_types: list[str] | None = None,
    tenant: str = "default",
) -> tuple[Any, list[Finding], str]:
    findings = detect_json(obj, include_types=include_types, tenant=tenant)
    mapping_id = str(uuid.uuid4())

    if not findings:
        return obj, [], mapping_id

    path_finding_map: dict[str, list[Finding]] = {}
    for f in findings:
        if f.field_path:
            path_finding_map.setdefault(f.field_path, []).append(f)

    def _apply(node: Any, path: str = "$") -> Any:
        if path in path_finding_map:
            if isinstance(node, str):
                fs = sorted(path_finding_map[path], key=lambda f: f.start, reverse=True)
                result = node
                for f in fs:
                    masked = mask_value(f.value, strategy, f.type)
                    result = result[:f.start] + masked + result[f.end:]
                return result

        if isinstance(node, dict):
            new_dict = {}
            for key, value in node.items():
                child_path = f"{path}.{key}"
                new_dict[key] = _apply(value, child_path)
            return new_dict

        if isinstance(node, list):
            new_list = []
            for idx, value in enumerate(node):
                child_path = f"{path}[{idx}]"
                new_list.append(_apply(value, child_path))
            return new_list

        return node

    masked_obj = _apply(obj, "$")
    return masked_obj, findings, mapping_id


def apply_mask_findings(text: str, findings: list[Finding], strategy: str) -> str:
    if not findings:
        return text
    sorted_fs = sorted(findings, key=lambda f: f.start, reverse=True)
    result = text
    for f in sorted_fs:
        masked = mask_value(f.value, strategy, f.type)
        result = result[:f.start] + masked + result[f.end:]
    return result
