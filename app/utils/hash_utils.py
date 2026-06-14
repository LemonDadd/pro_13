import hashlib
import re

from app.core.config import settings


def compute_value_hash(value: str) -> str:
    salted = f"{settings.hash_salt}:{value}"
    sha = hashlib.sha256(salted.encode("utf-8")).hexdigest()
    return f"{sha[:8]}:{len(value)}"


def is_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return not (a_end <= b_start or b_end <= a_start)


def merge_findings(findings: list) -> list:
    if not findings:
        return []
    sorted_findings = sorted(
        findings,
        key=lambda f: (f["start"], -f["end"], _priority_score(f.get("confidence", "med"))),
    )
    merged = []
    for f in sorted_findings:
        if not merged:
            merged.append(f)
            continue
        last = merged[-1]
        if is_overlap(last["start"], last["end"], f["start"], f["end"]):
            if f["end"] > last["end"]:
                merged[-1] = f
        else:
            merged.append(f)
    return merged


def _priority_score(confidence: str) -> int:
    return {"high": 3, "med": 2, "low": 1}.get(confidence, 0)


def is_whitelist_field(field_name: str, whitelist: list) -> bool:
    if not field_name or not whitelist:
        return False
    name_lower = field_name.lower().replace("_", "").replace("-", "")
    for w in whitelist:
        w_norm = w.lower().replace("_", "").replace("-", "")
        if w_norm in name_lower or name_lower in w_norm:
            return True
    return False
