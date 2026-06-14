import os
import re
import threading
import time
from typing import Optional

import yaml

from app.core.config import settings


class Rule:
    def __init__(self, type_name: str, config: dict):
        self.type_name = type_name
        self.description = config.get("description", "")
        self.pattern = config.get("pattern", "")
        self.confidence = config.get("confidence", "med")
        self.priority = config.get("priority", 50)
        self.validator = config.get("validator")
        self.enabled = config.get("enabled", True)
        self.regex = re.compile(self.pattern) if self.pattern else None


class RuleEngine:
    def __init__(self, rules_file: str):
        self.rules_file = rules_file
        self._rules: dict[str, Rule] = {}
        self._whitelist_fields: list[str] = []
        self._custom_rules: dict[str, dict] = {}
        self._last_mtime: float = 0
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._reload_thread: Optional[threading.Thread] = None
        self.load()

    def load(self):
        if not os.path.exists(self.rules_file):
            return
        with open(self.rules_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        with self._lock:
            self._whitelist_fields = data.get("whitelist_fields", []) or []
            self._custom_rules = data.get("custom_rules", {}) or {}

            rules_data = data.get("rules", {}) or {}
            rules = {}
            for name, cfg in rules_data.items():
                if not cfg.get("enabled", True):
                    continue
                rules[name] = Rule(name, cfg)

            for name, cfg in self._custom_rules.items():
                if not cfg.get("enabled", True):
                    continue
                rules[name] = Rule(name, cfg)

            self._rules = rules
            self._last_mtime = os.path.getmtime(self.rules_file)

    def _check_and_reload(self):
        if not os.path.exists(self.rules_file):
            return
        mtime = os.path.getmtime(self.rules_file)
        if mtime > self._last_mtime:
            self.load()

    def start_hot_reload(self, interval: int = 30):
        if self._reload_thread and self._reload_thread.is_alive():
            return

        def _runner():
            while not self._stop_event.is_set():
                try:
                    self._check_and_reload()
                except Exception:
                    pass
                self._stop_event.wait(interval)

        self._reload_thread = threading.Thread(target=_runner, daemon=True)
        self._reload_thread.start()

    def stop_hot_reload(self):
        self._stop_event.set()
        if self._reload_thread:
            self._reload_thread.join(timeout=2)

    def get_rules(self) -> list[Rule]:
        with self._lock:
            return sorted(self._rules.values(), key=lambda r: (-r.priority, r.type_name))

    def get_whitelist_fields(self) -> list[str]:
        with self._lock:
            return list(self._whitelist_fields)

    def add_custom_rule(self, type_name: str, config: dict, tenant: str = "default"):
        key = f"{tenant}:{type_name}" if tenant != "default" else type_name
        with self._lock:
            self._custom_rules[key] = config
            if config.get("enabled", True):
                self._rules[key] = Rule(key, config)

    def remove_custom_rule(self, type_name: str, tenant: str = "default"):
        key = f"{tenant}:{type_name}" if tenant != "default" else type_name
        with self._lock:
            self._custom_rules.pop(key, None)
            self._rules.pop(key, None)


_engine: Optional[RuleEngine] = None


def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine(settings.rules_file)
        if settings.rules_hot_reload:
            _engine.start_hot_reload(settings.rules_reload_interval)
    return _engine
