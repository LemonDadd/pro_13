import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import get_tenant_id
from app.core.database import get_db
from app.schemas.api import MaskRequest, MaskResponse, findings_to_response
from app.services.mask_service import mask_text, mask_json
from app.services.audit_service import record_audit

router = APIRouter(prefix="/mask", tags=["masking"])


@router.post("", response_model=MaskResponse)
def mask(
    request: MaskRequest,
    tenant_id: str = Depends(get_tenant_id),
    db: Session = Depends(get_db),
):
    if request.strategy not in ("middle", "hash", "remove"):
        raise HTTPException(status_code=400, detail="Invalid strategy. Use: middle, hash, remove")

    findings = []
    mapping_id = ""
    masked_text = None
    masked_json = None

    if request.text is not None:
        masked_text, findings, mapping_id = mask_text(
            request.text, strategy=request.strategy,
            include_types=request.include_types, tenant=tenant_id,
        )
        total_length = len(request.text)
    elif request.json_obj is not None:
        masked_json, findings, mapping_id = mask_json(
            request.json_obj, strategy=request.strategy,
            include_types=request.include_types, tenant=tenant_id,
        )
        total_length = len(json.dumps(request.json_obj))
    elif request.content is not None:
        if request.format == "json":
            try:
                json_data = json.loads(request.content)
                masked_json, findings, mapping_id = mask_json(
                    json_data, strategy=request.strategy,
                    include_types=request.include_types, tenant=tenant_id,
                )
                total_length = len(request.content)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid JSON content")
        else:
            masked_text, findings, mapping_id = mask_text(
                request.content, strategy=request.strategy,
                include_types=request.include_types, tenant=tenant_id,
            )
            total_length = len(request.content)
    else:
        raise HTTPException(status_code=400, detail="Either 'text', 'json', or 'content' must be provided")

    response_findings = findings_to_response(findings)

    record_audit(
        db=db, tenant_id=tenant_id, op="mask",
        findings=findings, total_length=total_length,
        strategy=request.strategy, mapping_id=mapping_id,
    )

    return MaskResponse(
        maskedText=masked_text,
        maskedJson=masked_json,
        mappingId=mapping_id,
        findings=response_findings,
        total=len(response_findings),
    )
