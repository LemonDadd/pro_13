import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

API_KEY = "test-api-key"
HEADERS = {"X-API-Key": API_KEY}


class TestAuth:
    def test_no_api_key(self, client):
        response = client.post("/v1/detect", json={"text": "test"})
        assert response.status_code == 401

    def test_invalid_api_key(self, client):
        response = client.post("/v1/detect", json={"text": "test"}, headers={"X-API-Key": "invalid"})
        assert response.status_code == 403

    def test_valid_api_key(self, client):
        response = client.post("/v1/detect", json={"text": "hello"}, headers=HEADERS)
        assert response.status_code == 200


class TestDetectEndpoint:
    def test_detect_text_phone(self, client):
        response = client.post(
            "/v1/detect",
            json={"text": "手机号 13812345678"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        findings = data["findings"]
        assert findings[0]["type"] == "PHONE_CN"
        assert "valueHash" in findings[0]
        assert "value" not in findings[0]

    def test_detect_json(self, client):
        response = client.post(
            "/v1/detect",
            json={"json": {"user": {"phone": "13812345678"}}},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        assert data["findings"][0]["fieldPath"] == "$.user.phone"

    def test_detect_include_types(self, client):
        response = client.post(
            "/v1/detect",
            json={"text": "手机13812345678和邮箱test@example.com", "include_types": ["PHONE_CN"]},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 1
        assert data["findings"][0]["type"] == "PHONE_CN"

    def test_detect_empty_body(self, client):
        response = client.post("/v1/detect", json={}, headers=HEADERS)
        assert response.status_code == 400

    def test_detect_whitelist_not_in_response(self, client):
        response = client.post(
            "/v1/detect",
            json={"json": {"password": "13812345678"}},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        for f in data["findings"]:
            assert "value" not in f


class TestMaskEndpoint:
    def test_mask_text_middle(self, client):
        response = client.post(
            "/v1/mask",
            json={"text": "手机号 13812345678", "strategy": "middle"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert "138****5678" in data["maskedText"]
        assert data["mappingId"]
        assert data["total"] >= 1

    def test_mask_text_hash(self, client):
        response = client.post(
            "/v1/mask",
            json={"text": "手机号 13812345678", "strategy": "hash"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert "[HASH:" in data["maskedText"]
        assert "13812345678" not in data["maskedText"]

    def test_mask_text_remove(self, client):
        response = client.post(
            "/v1/mask",
            json={"text": "手机号 13812345678", "strategy": "remove"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert "13812345678" not in data["maskedText"]

    def test_mask_json(self, client):
        response = client.post(
            "/v1/mask",
            json={"json": {"phone": "13812345678", "name": "张三"}, "strategy": "middle"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["json"]["phone"] == "138****5678"
        assert data["json"]["name"] == "张三"

    def test_mask_invalid_strategy(self, client):
        response = client.post(
            "/v1/mask",
            json={"text": "test", "strategy": "invalid"},
            headers=HEADERS,
        )
        assert response.status_code == 400

    def test_mask_no_original_value(self, client):
        response = client.post(
            "/v1/mask",
            json={"text": "手机号13812345678", "strategy": "middle"},
            headers=HEADERS,
        )
        data = response.json()
        for f in data["findings"]:
            assert "value" not in f


class TestStatsEndpoint:
    def test_stats_daily(self, client):
        client.post(
            "/v1/detect",
            json={"text": "手机号13812345678"},
            headers=HEADERS,
        )
        response = client.get("/v1/stats/daily", headers=HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert "date" in data
        assert "total_detect" in data
        assert "total_mask" in data
        assert "type_distribution" in data


class TestBatchEndpoint:
    def test_batch_submit(self, client):
        content = "这是测试文本，手机号 13812345678"
        files = {"file": ("test.txt", content.encode("utf-8"), "text/plain")}
        data = {"strategy": "middle", "format": "text"}
        response = client.post(
            "/v1/batch/mask",
            files=files,
            data=data,
            headers=HEADERS,
        )
        assert response.status_code == 200
        job_data = response.json()
        assert "jobId" in job_data
        assert job_data["status"] in ("pending", "processing")

        job_id = job_data["jobId"]
        status_response = client.get(f"/v1/batch/{job_id}", headers=HEADERS)
        assert status_response.status_code == 200
        assert status_response.json()["jobId"] == job_id

    def test_batch_completed_returns_masked_content(self, client):
        from app.core.database import SessionLocal
        from app.models.batch import BatchJob
        from datetime import datetime, timezone
        import os

        content = "手机号 13812345678"
        files = {"file": ("test2.txt", content.encode("utf-8"), "text/plain")}
        data = {"strategy": "middle", "format": "text"}
        response = client.post(
            "/v1/batch/mask",
            files=files,
            data=data,
            headers=HEADERS,
        )
        assert response.status_code == 200
        job_id = response.json()["jobId"]

        output_path = os.path.join("data", "batch", f"{job_id}_output.txt")
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write("手机号 138****5678")

        db = SessionLocal()
        try:
            job = db.query(BatchJob).filter(BatchJob.id == job_id).first()
            job.status = "completed"
            job.output_path = output_path
            job.output_size = len("手机号 138****5678")
            job.hit_counts = {"PHONE_CN": 1}
            job.started_at = datetime.now(timezone.utc)
            job.completed_at = datetime.now(timezone.utc)
            db.commit()
        finally:
            db.close()

        status_response = client.get(f"/v1/batch/{job_id}", headers=HEADERS)
        assert status_response.status_code == 200
        status_data = status_response.json()
        assert status_data["status"] == "completed"
        assert status_data["maskedContent"] is not None
        assert "138****5678" in status_data["maskedContent"]

    def test_batch_not_found(self, client):
        response = client.get("/v1/batch/nonexistent-id", headers=HEADERS)
        assert response.status_code == 404


class TestBugFixes:
    def test_hash_format_has_closing_bracket(self, client):
        response = client.post(
            "/v1/mask",
            json={"text": "手机号 13812345678", "strategy": "hash"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        masked = data["maskedText"]
        assert "[HASH:" in masked
        assert masked.endswith("]") or masked.count("]") >= masked.count("[HASH:")

    def test_whitelist_not_in_audit_hit_counts(self, client):
        from app.core.database import SessionLocal
        from app.models.audit import AuditLog

        response = client.post(
            "/v1/mask",
            json={"json": {"password": "13812345678", "phone": "13987654321"}, "strategy": "middle"},
            headers=HEADERS,
        )
        assert response.status_code == 200

        db = SessionLocal()
        try:
            latest = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
            assert latest is not None
            hit_counts = latest.hit_counts or {}
            assert hit_counts.get("PHONE_CN", 0) == 1
        finally:
            db.close()

    def test_mask_json_response_format(self, client):
        response = client.post(
            "/v1/mask",
            json={"json": {"phone": "13812345678"}, "strategy": "middle"},
            headers=HEADERS,
        )
        assert response.status_code == 200
        data = response.json()
        assert "json" in data
        assert data["json"] is not None
        assert data["json"]["phone"] == "138****5678"


class TestRulesAPI:
    def test_list_builtin_rules(self, client):
        response = client.get("/v1/rules/builtin", headers=HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert data["total"] > 0
        rule_types = {r["type_name"] for r in data["rules"]}
        assert "PHONE_CN" in rule_types
        assert "EMAIL" in rule_types

    def test_add_and_list_custom_rule(self, client):
        response = client.post(
            "/v1/rules/custom",
            json={
                "type_name": "CUSTOM_ORDER_NO",
                "pattern": r"ORD\d{8}",
                "description": "订单号",
                "confidence": "high",
                "priority": 100,
                "enabled": True,
            },
            headers=HEADERS,
        )
        assert response.status_code == 201
        assert response.json()["type_name"] == "CUSTOM_ORDER_NO"

        list_resp = client.get("/v1/rules/custom", headers=HEADERS)
        assert list_resp.status_code == 200
        assert list_resp.json()["total"] >= 1

        detect_resp = client.post(
            "/v1/detect",
            json={"text": "订单号 ORD20240101"},
            headers=HEADERS,
        )
        assert detect_resp.status_code == 200
        types = {f["type"] for f in detect_resp.json()["findings"]}
        assert "CUSTOM_ORDER_NO" in types

    def test_delete_custom_rule(self, client):
        client.post(
            "/v1/rules/custom",
            json={
                "type_name": "TO_DELETE",
                "pattern": r"DEL\d+",
                "description": "to be deleted",
                "confidence": "med",
                "priority": 50,
                "enabled": True,
            },
            headers=HEADERS,
        )

        del_resp = client.delete("/v1/rules/custom/TO_DELETE", headers=HEADERS)
        assert del_resp.status_code == 204

    def test_add_invalid_regex(self, client):
        response = client.post(
            "/v1/rules/custom",
            json={
                "type_name": "BAD_REGEX",
                "pattern": "[invalid(",
                "confidence": "med",
                "priority": 50,
                "enabled": True,
            },
            headers=HEADERS,
        )
        assert response.status_code == 400

    def test_cannot_override_builtin(self, client):
        response = client.post(
            "/v1/rules/custom",
            json={
                "type_name": "PHONE_CN",
                "pattern": r"123",
                "confidence": "med",
                "priority": 50,
                "enabled": True,
            },
            headers=HEADERS,
        )
        assert response.status_code == 400


class TestNormalize:
    def test_fullwidth_digits_detection(self, client):
        text = "手机号 １３８１２３４５６７８"
        response = client.post(
            "/v1/detect",
            json={"text": text},
            headers=HEADERS,
        )
        assert response.status_code == 200
        types = {f["type"] for f in response.json()["findings"]}
        assert "PHONE_CN" in types

    def test_zero_width_chars_detection(self, client):
        text = "手机号 138\u200b1234\u200c5678"
        response = client.post(
            "/v1/detect",
            json={"text": text},
            headers=HEADERS,
        )
        assert response.status_code == 200
        types = {f["type"] for f in response.json()["findings"]}
        assert "PHONE_CN" in types

    def test_normalize_preserves_original_positions(self, client):
        text = "手机号 １３８１２３４５６７８ end"
        response = client.post(
            "/v1/detect",
            json={"text": text},
            headers=HEADERS,
        )
        assert response.status_code == 200
        findings = response.json()["findings"]
        assert len(findings) >= 1
        phone_finding = [f for f in findings if f["type"] == "PHONE_CN"][0]
        assert phone_finding["start"] >= 0
        assert phone_finding["end"] <= len(text)
        assert "１３８１２３４５６７８" in text[phone_finding["start"]:phone_finding["end"]]


class TestNERDetector:
    def test_ner_disabled_by_default(self, client):
        from app.detectors.ner import get_detector_pipeline
        pipeline = get_detector_pipeline()
        assert pipeline._ner is None or not getattr(pipeline._ner, "enabled", False)

    def test_ner_enable_disable_no_crash(self, client):
        from app.detectors.ner import get_detector_pipeline
        pipeline = get_detector_pipeline()
        try:
            pipeline.enable_ner()
            pipeline.enable_ner()
            pipeline.disable_ner()
            pipeline.disable_ner()
        except Exception as e:
            pytest.fail(f"NER enable/disable crashed: {e}")

    def test_ner_run_extra_detectors_empty_by_default(self, client):
        from app.detectors.ner import get_detector_pipeline
        pipeline = get_detector_pipeline()
        result = pipeline.run_extra_detectors("测试文本")
        assert isinstance(result, list)
        assert len(result) == 0


class TestHealthEndpoint:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
