from collections import Counter
from datetime import datetime, date, timezone

from sqlalchemy.orm import Session

from app.models.audit import AuditLog


def record_audit(
    db: Session,
    tenant_id: str,
    op: str,
    findings: list,
    total_length: int = 0,
    strategy: str | None = None,
    mapping_id: str | None = None,
) -> AuditLog:
    hit_counts = Counter(f.type for f in findings)
    log = AuditLog(
        tenant_id=tenant_id,
        op=op,
        hit_counts=dict(hit_counts),
        total_length=total_length,
        strategy=strategy,
        mapping_id=mapping_id,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def get_daily_stats(db: Session, tenant_id: str, target_date: date | None = None) -> dict:
    if target_date is None:
        target_date = datetime.now(timezone.utc).date()

    start = datetime.combine(target_date, datetime.min.time())
    end = datetime.combine(target_date, datetime.max.time())

    logs = (
        db.query(AuditLog)
        .filter(
            AuditLog.tenant_id == tenant_id,
            AuditLog.created_at >= start,
            AuditLog.created_at <= end,
        )
        .all()
    )

    total_detect = 0
    total_mask = 0
    type_distribution: Counter = Counter()

    for log in logs:
        if log.op == "detect":
            total_detect += 1
        elif log.op == "mask":
            total_mask += 1
        if log.hit_counts:
            for t, c in log.hit_counts.items():
                type_distribution[t] += c

    return {
        "date": target_date.isoformat(),
        "total_detect": total_detect,
        "total_mask": total_mask,
        "type_distribution": dict(type_distribution),
    }
