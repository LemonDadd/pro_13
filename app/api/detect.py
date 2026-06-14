from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_id
from app.core.database import get_db
from app.detectors.base import detect_text, detect_json
from app.schemas.api import DetectRequest, DetectResponse, FindingResponse
from app.services.audit_service import record_audit

router = APIRouter(prefix="/detect", tags=["detection"])


@router.post("", response_model=DetectResponse)
def detect(
    request: DetectRequest,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    findings = []

    if request.text is not None:
        findings = detect_text(request.text, include_types=request.include_types, tenant=tenant_id)
        total_length = len(request.text)
    elif request.json_obj is not None:
        findings = detect_json(request.json_obj, include_types=request.include_types, tenant=tenant_id)
        import json
        total_length = len(json.dumps(request.json_obj))
    else:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="Either 'text' or 'json' must be provided")

    response_findings = [
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

    record_audit(
        db=db,
        tenant_id=tenant_id,
        op="detect",
        findings=findings,
        total_length=total_length,
    )

    return DetectResponse(findings=response_findings, total=len(response_findings))
