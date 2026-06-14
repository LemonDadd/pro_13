from abc import ABC, abstractmethod
from typing import Any

from app.detectors.base import Finding


class BaseDetector(ABC):
    name: str = "base"

    @abstractmethod
    def detect(self, text: str, **kwargs) -> list[Finding]:
        pass

    def detect_json(self, obj: Any, **kwargs) -> list[Finding]:
        return []


class NERDetector(BaseDetector):
    name: str = "ner"

    def __init__(self, enabled: bool = False, model_path: str | None = None):
        self.enabled = enabled
        self.model_path = model_path
        self._model = None
        if enabled:
            self._load_model()

    def _load_model(self):
        pass

    def detect(self, text: str, **kwargs) -> list[Finding]:
        if not self.enabled or not text:
            return []
        return self._mock_detect(text)

    def _mock_detect(self, text: str) -> list[Finding]:
        return []


class DetectorPipeline:
    def __init__(self):
        self._detectors: list[BaseDetector] = []
        self._ner: NERDetector | None = None

    def add_detector(self, detector: BaseDetector):
        self._detectors.append(detector)

    def enable_ner(self, model_path: str | None = None):
        if not self._ner:
            self._ner = NERDetector(enabled=True, model_path=model_path)
            self.add_detector(self._ner)

    def disable_ner(self):
        if self._ner:
            self._ner.enabled = False
            if self._ner in self._detectors:
                self._detectors.remove(self._ner)
            self._ner = None

    def run_extra_detectors(self, text: str, **kwargs) -> list[Finding]:
        all_findings = []
        for detector in self._detectors:
            try:
                findings = detector.detect(text, **kwargs)
                all_findings.extend(findings)
            except Exception as e:
                print(f"[DetectorPipeline] {detector.name} error: {e}")
        return all_findings


_pipeline: DetectorPipeline | None = None


def get_detector_pipeline() -> DetectorPipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = DetectorPipeline()
    return _pipeline
