from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String, JSON

from app.core.database import Base


def _utc_now():
    return datetime.now(timezone.utc)


class BatchJob(Base):
    __tablename__ = "batch_jobs"

    id = Column(String(64), primary_key=True)
    tenant_id = Column(String(64), index=True, nullable=False)
    status = Column(String(16), index=True, default="pending")
    format = Column(String(16), default="text")
    strategy = Column(String(16), default="middle")
    include_types = Column(JSON, nullable=True)
    input_size = Column(Integer, default=0)
    output_size = Column(Integer, default=0)
    hit_counts = Column(JSON, nullable=True)
    error_message = Column(String(512), nullable=True)
    output_path = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=_utc_now, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
