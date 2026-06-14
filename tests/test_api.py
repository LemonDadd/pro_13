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

    def test_batch_not_found(self, client):
        response = client.get("/v1/batch/nonexistent-id", headers=HEADERS)
        assert response.status_code == 404


class TestHealthEndpoint:
    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
