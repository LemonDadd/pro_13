import os
import json
import threading
import time
from datetime import datetime, timezone
from collections import Counter

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.batch import BatchJob
from app.services.mask_service import mask_text, mask_json


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class BatchWorker:
    def __init__(self):
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._interval = settings.batch_worker_interval

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        while not self._stop_event.is_set():
            try:
                self._process_next_job()
            except Exception as e:
                print(f"[BatchWorker] Error in loop: {e}")
            self._stop_event.wait(self._interval)

    def _process_next_job(self):
        db = SessionLocal()
        job = None
        job_id = None
        try:
            job = (
                db.query(BatchJob)
                .filter(BatchJob.status == "pending")
                .order_by(BatchJob.created_at.asc())
                .first()
            )
            if not job:
                return

            job_id = job.id
            job.status = "processing"
            job.started_at = _utc_now()
            db.commit()

            input_path = os.path.join("data", "batch", f"{job.id}_input.txt")
            output_path = os.path.join("data", "batch", f"{job.id}_output.txt")

            if not os.path.exists(input_path):
                job.status = "failed"
                job.error_message = "Input file not found"
                job.completed_at = _utc_now()
                db.commit()
                return

            with open(input_path, "r", encoding="utf-8") as f:
                content = f.read()

            all_findings = []
            if job.format == "json":
                try:
                    json_data = json.loads(content)
                    masked_data, findings, _ = mask_json(
                        json_data,
                        strategy=job.strategy,
                        include_types=job.include_types,
                        tenant=job.tenant_id,
                    )
                    all_findings = findings
                    with open(output_path, "w", encoding="utf-8") as f:
                        json.dump(masked_data, f, ensure_ascii=False, indent=2)
                except json.JSONDecodeError as e:
                    job.status = "failed"
                    job.error_message = f"Invalid JSON: {str(e)}"
                    job.completed_at = _utc_now()
                    db.commit()
                    return
            else:
                masked_text, findings, _ = mask_text(
                    content,
                    strategy=job.strategy,
                    include_types=job.include_types,
                    tenant=job.tenant_id,
                )
                all_findings = findings
                with open(output_path, "w", encoding="utf-8") as f:
                    f.write(masked_text)

            filtered_findings = [f for f in all_findings if not getattr(f, "is_whitelist", False)]
            hit_counts = Counter(f.type for f in filtered_findings)
            output_size = os.path.getsize(output_path) if os.path.exists(output_path) else 0

            job.status = "completed"
            job.output_size = output_size
            job.hit_counts = dict(hit_counts)
            job.output_path = output_path
            job.completed_at = _utc_now()
            db.commit()

        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            try:
                if job_id:
                    job_ref = db.query(BatchJob).filter(BatchJob.id == job_id).first()
                    if job_ref:
                        job_ref.status = "failed"
                        job_ref.error_message = str(e)[:500]
                        job_ref.completed_at = _utc_now()
                        db.commit()
            except Exception as inner_e:
                print(f"[BatchWorker] Failed to update job status: {inner_e}")
        finally:
            try:
                db.close()
            except Exception:
                pass


_worker: BatchWorker | None = None


def get_batch_worker() -> BatchWorker:
    global _worker
    if _worker is None:
        _worker = BatchWorker()
    return _worker
