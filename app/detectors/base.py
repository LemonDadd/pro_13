from typing import Any

from app.detectors.finding import Finding
from app.detectors.pipeline import run_text_pipeline, run_json_pipeline

__all__ = ["Finding", "detect_text", "detect_json"]


def detect_text(
    text: str,
    include_types: list[str] | None = None,
    tenant: str = "default",
) -> list[Finding]:
    return run_text_pipeline(text, include_types=include_types, tenant=tenant)


def detect_json(
    obj: Any,
    include_types: list[str] | None = None,
    tenant: str = "default",
) -> list[Finding]:
    return run_json_pipeline(obj, include_types=include_types, tenant=tenant)
