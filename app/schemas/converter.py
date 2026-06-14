from app.detectors.finding import Finding
from app.schemas.common import FindingResponse


def findings_to_response(findings: list[Finding]) -> list[FindingResponse]:
    """
    将内部 Finding 对象转为公开的 FindingResponse。
    过滤 is_whitelist=True 的项。
    """
    return [
        FindingResponse(
            type=f.type,
            start=f.start,
            end=f.end,
            length=f.length,
            valueHash=f.value_hash,
            confidence=f.confidence,
            fieldPath=f.field_path,
        )
        for f in findings
        if not f.is_whitelist
    ]
