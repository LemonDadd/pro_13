from app.detectors.finding import Finding
from app.detectors.ner import BaseDetector
from app.rules.engine import Rule, get_rule_engine
from app.utils.normalize import normalize_text, map_position
from app.utils.validators import run_validator


def _downgrade_confidence(confidence: str) -> str:
    if confidence == "high":
        return "med"
    if confidence == "med":
        return "low"
    return "low"


class RegexDetector(BaseDetector):
    """
    基于规则正则的检测器。
    返回未合并的原始 Finding 列表，由调用方统一 merge。
    """
    name: str = "regex"

    def detect(self, text: str, **kwargs) -> list[Finding]:
        if not text:
            return []

        include_types: list[str] | None = kwargs.get("include_types")
        tenant: str = kwargs.get("tenant", "default")

        normalized, pos_map = normalize_text(text)
        if not normalized:
            return []

        engine = get_rule_engine()
        rules = engine.get_rules(tenant=tenant)

        findings: list[Finding] = []
        for rule in rules:
            if include_types and rule.type_name not in include_types:
                continue
            if not rule.regex:
                continue
            findings.extend(self._scan_rule(text, normalized, pos_map, rule))
        return findings

    def _scan_rule(
        self,
        original_text: str,
        normalized: str,
        pos_map: list[int],
        rule: Rule,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for match in rule.regex.finditer(normalized):
            norm_start = match.start()
            norm_end = match.end()
            orig_start, orig_end = map_position(norm_start, norm_end, pos_map)
            orig_value = original_text[orig_start:orig_end]

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
        return findings
