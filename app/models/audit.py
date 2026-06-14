from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, JSON

from app.core.database import Base


def _utc_now():
    return datetime.now(timezone.utc)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tenant_id = Column(String(64), index=True, nullable=False)
    op = Column(String(16), index=True, nullable=False)
    hit_counts = Column(JSON, nullable=False, default=dict)
    total_length = Column(Integer, default=0)
    strategy = Column(String(16), nullable=True)
    mapping_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=_utc_now, index=True)
