import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app.detectors.base import detect_text, detect_json, Finding
from app.services.mask_service import mask_text, mask_json, mask_value
from app.utils.validators import validate_id_card, validate_luhn
from app.rules.engine import get_rule_engine


class TestIdCardValidator:
    def test_valid_id_card(self):
        assert validate_id_card("110101199003071006") is True

    def test_invalid_id_card_checksum(self):
        assert validate_id_card("110101199003076510") is False

    def test_invalid_id_card_length(self):
        assert validate_id_card("12345") is False

    def test_invalid_id_card_format(self):
        assert validate_id_card("000000000000000000") is False


class TestLuhnValidator:
    def test_valid_luhn(self):
        assert validate_luhn("4532015112830366") is True

    def test_invalid_luhn(self):
        assert validate_luhn("4532015112830367") is False

    def test_empty_luhn(self):
        assert validate_luhn("") is False


class TestDetectText:
    def test_detect_phone(self):
        findings = detect_text("我的手机号是13812345678")
        assert len(findings) == 1
        assert findings[0].type == "PHONE_CN"
        assert findings[0].value == "13812345678"

    def test_detect_email(self):
        findings = detect_text("联系我 test@example.com")
        assert len(findings) >= 1
        types = [f.type for f in findings]
        assert "EMAIL" in types

    def test_detect_id_card(self):
        findings = detect_text("身份证号110101199003076515")
        assert len(findings) >= 1
        id_findings = [f for f in findings if f.type == "ID_CARD"]
        assert len(id_findings) >= 1

    def test_detect_id_card_invalid_checksum(self):
        findings = detect_text("身份证号110101199003076510")
        id_findings = [f for f in findings if f.type == "ID_CARD"]
        if id_findings:
            assert id_findings[0].confidence == "med"

    def test_detect_aws_key(self):
        findings = detect_text("AKIAIOSFODNN7EXAMPLE")
        assert len(findings) >= 1
        assert findings[0].type == "AWS_KEY"

    def test_detect_private_ip(self):
        findings = detect_text("服务器地址 192.168.1.100")
        ip_findings = [f for f in findings if f.type == "IP_PRIVATE"]
        assert len(ip_findings) >= 1

    def test_detect_multiple(self):
        text = "手机 13812345678 和邮箱 test@example.com"
        findings = detect_text(text)
        types = {f.type for f in findings}
        assert "PHONE_CN" in types
        assert "EMAIL" in types

    def test_detect_include_types(self):
        text = "手机 13812345678 和邮箱 test@example.com"
        findings = detect_text(text, include_types=["PHONE_CN"])
        assert len(findings) == 1
        assert findings[0].type == "PHONE_CN"

    def test_detect_empty_text(self):
        findings = detect_text("")
        assert len(findings) == 0


class TestDetectJson:
    def test_detect_simple_json(self):
        data = {"user": {"phone": "13812345678", "email": "test@example.com"}}
        findings = detect_json(data)
        assert len(findings) >= 2
        paths = {f.field_path for f in findings}
        assert "$.user.phone" in paths
        assert "$.user.email" in paths

    def test_detect_json_array(self):
        data = {"phones": ["13812345678", "13987654321"]}
        findings = detect_json(data)
        assert len(findings) == 2
        paths = {f.field_path for f in findings}
        assert "$.phones[0]" in paths
        assert "$.phones[1]" in paths

    def test_detect_whitelist_field(self):
        data = {"password": "13812345678"}
        findings = detect_json(data)
        assert len(findings) == 1
        assert findings[0].is_whitelist is True

    def test_detect_nested_whitelist(self):
        data = {"user": {"password": "my-secret-pass"}}
        findings = detect_json(data)
        for f in findings:
            if f.field_path == "$.user.password":
                assert f.is_whitelist is True


class TestMaskValue:
    def test_mask_phone_middle(self):
        result = mask_value("13812345678", "middle", "PHONE_CN")
        assert result == "138****5678"

    def test_mask_id_card_middle(self):
        result = mask_value("110101199003076515", "middle", "ID_CARD")
        assert result.startswith("110")
        assert result.endswith("6515")
        assert "*" in result

    def test_mask_email_middle(self):
        result = mask_value("testuser@example.com", "middle", "EMAIL")
        assert result.startswith("te")
        assert "@example.com" in result
        assert "*" in result

    def test_mask_hash(self):
        result = mask_value("13812345678", "hash", "PHONE_CN")
        assert result.startswith("[HASH:")
        assert result.endswith("]")
        assert ":" in result

    def test_mask_remove(self):
        result = mask_value("13812345678", "remove", "PHONE_CN")
        assert result == ""

    def test_mask_bank_card_middle(self):
        result = mask_value("6222021234567890123", "middle", "BANK_CARD")
        assert result.startswith("6222")
        assert result.endswith("0123")
        assert "*" in result


class TestMaskText:
    def test_mask_text_phone(self):
        masked, findings, mapping_id = mask_text("手机 13812345678 号", strategy="middle")
        assert "138****5678" in masked
        assert len(findings) == 1
        assert mapping_id

    def test_mask_text_multiple(self):
        text = "手机13812345678和邮箱test@example.com"
        masked, findings, _ = mask_text(text, strategy="middle")
        assert "138****5678" in masked
        assert "@" in masked
        assert len(findings) >= 2

    def test_mask_text_no_finding(self):
        text = "这段文字没有敏感数据"
        masked, findings, _ = mask_text(text, strategy="middle")
        assert masked == text
        assert len(findings) == 0

    def test_mask_text_index_order(self):
        text = "13812345678 和 13987654321"
        masked, findings, _ = mask_text(text, strategy="middle")
        assert masked.count("*") > 0
        original_positions = [(f.start, f.end) for f in findings]
        assert all(s < e for s, e in original_positions)

    def test_mask_text_hash_strategy(self):
        text = "手机号13812345678"
        masked, findings, _ = mask_text(text, strategy="hash")
        assert "[HASH:" in masked
        assert masked.count("]") >= 1
        assert "13812345678" not in masked


class TestMaskJson:
    def test_mask_json_simple(self):
        data = {"phone": "13812345678", "name": "张三"}
        masked, findings, _ = mask_json(data, strategy="middle")
        assert masked["phone"] == "138****5678"
        assert masked["name"] == "张三"
        assert len(findings) == 1

    def test_mask_json_nested(self):
        data = {"user": {"phone": "13812345678", "email": "test@example.com"}}
        masked, findings, _ = mask_json(data, strategy="middle")
        assert masked["user"]["phone"] == "138****5678"
        assert len(findings) >= 2

    def test_mask_json_array(self):
        data = {"phones": ["13812345678", "13987654321"]}
        masked, findings, _ = mask_json(data, strategy="middle")
        assert masked["phones"][0] == "138****5678"
        assert masked["phones"][1] == "139****4321"
        assert len(findings) == 2

    def test_mask_json_include_types(self):
        data = {"phone": "13812345678", "email": "test@example.com"}
        masked, findings, _ = mask_json(data, strategy="middle", include_types=["PHONE_CN"])
        assert masked["phone"] == "138****5678"
        assert masked["email"] == "test@example.com"
        assert len(findings) == 1


class TestRuleEngine:
    def test_load_rules(self):
        engine = get_rule_engine()
        rules = engine.get_rules()
        assert len(rules) > 0
        rule_types = {r.type_name for r in rules}
        assert "PHONE_CN" in rule_types
        assert "EMAIL" in rule_types

    def test_whitelist_fields(self):
        engine = get_rule_engine()
        whitelist = engine.get_whitelist_fields()
        assert len(whitelist) > 0
        assert "password" in whitelist

    def test_rule_priority(self):
        engine = get_rule_engine()
        rules = engine.get_rules()
        for i in range(len(rules) - 1):
            assert rules[i].priority >= rules[i + 1].priority


class TestValueHash:
    def test_hash_consistency(self):
        from app.utils.hash_utils import compute_value_hash
        h1 = compute_value_hash("test")
        h2 = compute_value_hash("test")
        assert h1 == h2

    def test_hash_different_values(self):
        from app.utils.hash_utils import compute_value_hash
        h1 = compute_value_hash("test1")
        h2 = compute_value_hash("test2")
        assert h1 != h2

    def test_hash_includes_length(self):
        from app.utils.hash_utils import compute_value_hash
        h = compute_value_hash("13812345678")
        assert ":11" in h


class TestTenantRuleIsolation:
    def test_rules_isolated_by_tenant(self):
        engine = get_rule_engine()
        engine.add_custom_rule(
            "CUSTOM_TENANT_A",
            {
                "description": "Tenant A custom rule",
                "pattern": r'\bTENANT_A_TOKEN_\w+\b',
                "confidence": "high",
                "priority": 200,
                "enabled": True,
            },
            tenant="tenant_a",
        )
        tenant_a_rules = {r.type_name for r in engine.get_rules(tenant="tenant_a")}
        tenant_b_rules = {r.type_name for r in engine.get_rules(tenant="tenant_b")}

        assert "CUSTOM_TENANT_A" in tenant_a_rules
        assert "CUSTOM_TENANT_A" not in tenant_b_rules

        findings_a = detect_text("TENANT_A_TOKEN_abc123", tenant="tenant_a")
        findings_b = detect_text("TENANT_A_TOKEN_abc123", tenant="tenant_b")

        assert len(findings_a) == 1
        assert findings_a[0].type == "CUSTOM_TENANT_A"
        assert len(findings_b) == 0

        engine.remove_custom_rule("CUSTOM_TENANT_A", tenant="tenant_a")

    def test_default_rules_available_to_all_tenants(self):
        engine = get_rule_engine()
        rules_default = {r.type_name for r in engine.get_rules(tenant="default")}
        rules_other = {r.type_name for r in engine.get_rules(tenant="some_tenant")}

        assert "PHONE_CN" in rules_default
        assert "PHONE_CN" in rules_other


class TestWhitelistAuditExclusion:
    def test_whitelist_not_in_audit_hit_counts(self):
        from collections import Counter
        from app.services.audit_service import record_audit

        data = {
            "password": "13812345678",
            "phone": "13987654321",
        }
        findings = detect_json(data)

        has_whitelist = any(f.is_whitelist for f in findings)
        assert has_whitelist

        filtered = [f for f in findings if not getattr(f, "is_whitelist", False)]
        hit_counts = Counter(f.type for f in filtered)

        assert "PHONE_CN" in hit_counts
        assert hit_counts["PHONE_CN"] == 1


class TestBatchWorkerRobustness:
    def test_worker_exception_safe(self):
        import threading
        from app.workers.batch_worker import BatchWorker

        worker = BatchWorker()

        def _fake_process():
            raise RuntimeError("simulated error")

        worker._process_next_job = _fake_process

        t = threading.Thread(target=worker._run, daemon=True)
        t.start()
        worker._stop_event.set()
        t.join(timeout=2)
        assert not t.is_alive()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
