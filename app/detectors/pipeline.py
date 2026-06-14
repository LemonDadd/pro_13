from typing import Any

from app.detectors.finding import Finding
from app.detectors.regex_detector import RegexDetector
from app.detectors.ner import get_detector_pipeline
from app.utils.hash_utils import merge_findings
from app.utils.json_traverse import traverse_json, get_field_name
from app.utils.hash_utils import is_whitelist_field
from app.rules.engine import get_rule_engine


_REGEX_DETECTOR = RegexDetector()


def _to_finding_objects(merged_dicts: list[dict]) -> list[Finding]:
    return [
        Finding(
            type=fd["type"],
            start=fd["start"],
            end=fd["end"],
            value=fd["value"],
            confidence=fd.get("confidence", "med"),
        )
        for fd in merged_dicts
    ]


def run_text_pipeline(
    text: str,
    include_types: list[str] | None = None,
    tenant: str = "default",
) -> list[Finding]:
    """
    文本检测统一管道：
      1. RegexDetector 做 normalize + 正则扫描（含校验位降级）
      2. DetectorPipeline 跑 NER 等扩展
      3. merge_findings 统一一次合并
    """
    if not text:
        return []

    regex_findings = _REGEX_DETECTOR.detect(text, include_types=include_types, tenant=tenant)

    pipeline = get_detector_pipeline()
    extra_findings = pipeline.run_extra_detectors(text, include_types=include_types, tenant=tenant)

    all_dicts = [f.to_dict(include_value=True) for f in regex_findings] + [
        f.to_dict(include_value=True) for f in extra_findings
    ]
    if not all_dicts:
        return []

    merged = merge_findings(all_dicts)
    return _to_finding_objects(merged)


def run_json_pipeline(
    obj: Any,
    include_types: list[str] | None = None,
    tenant: str = "default",
) -> list[Finding]:
    """
    JSON 检测管道：
      - 遍历所有字符串节点
      - 每个节点走 run_text_pipeline
      - 打上 field_path / is_whitelist 标记
    """
    engine = get_rule_engine()
    whitelist = engine.get_whitelist_fields()
    all_findings: list[Finding] = []

    for path, value in traverse_json(obj):
        if not isinstance(value, str) or not value:
            continue
        field_name = get_field_name(path)
        text_findings = run_text_pipeline(value, include_types=include_types, tenant=tenant)
        for f in text_findings:
            f.field_path = path
            if field_name and is_whitelist_field(field_name, whitelist):
                f.is_whitelist = True
            all_findings.append(f)

    return all_findings
