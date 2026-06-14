from abc import ABC, abstractmethod
from typing import Any

from app.detectors.finding import Finding


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
            try:
                self._load_model()
            except Exception as e:
                print(f"[NERDetector] Failed to load model: {e}")
                self.enabled = False

    def _load_model(self):
        pass

    def detect(self, text: str, **kwargs) -> list[Finding]:
        if not self.enabled or not text:
            return []
        try:
            return self._mock_detect(text)
        except Exception as e:
            print(f"[NERDetector] detect error: {e}")
            return []

    def _mock_detect(self, text: str) -> list[Finding]:
        return []


class DetectorPipeline:
    def __init__(self):
        self._detectors: list[BaseDetector] = []
        self._ner: NERDetector | None = None

    def add_detector(self, detector: BaseDetector):
        try:
            if detector not in self._detectors:
                self._detectors.append(detector)
        except Exception as e:
            print(f"[DetectorPipeline] add_detector error: {e}")

    def enable_ner(self, model_path: str | None = None):
        try:
            if self._ner and self._ner.enabled:
                return
            self._ner = NERDetector(enabled=True, model_path=model_path)
            if self._ner.enabled:
                self.add_detector(self._ner)
            else:
                self._ner = None
        except Exception as e:
            print(f"[DetectorPipeline] enable_ner error: {e}")
            self._ner = None

    def disable_ner(self):
        try:
            if self._ner:
                self._ner.enabled = False
                if self._ner in self._detectors:
                    self._detectors.remove(self._ner)
                self._ner = None
        except Exception as e:
            print(f"[DetectorPipeline] disable_ner error: {e}")
            self._ner = None

    def run_extra_detectors(self, text: str, **kwargs) -> list[Finding]:
        all_findings = []
        for detector in list(self._detectors):
            try:
                findings = detector.detect(text, **kwargs)
                if findings:
                    all_findings.extend(findings)
            except Exception as e:
                print(f"[DetectorPipeline] {detector.name} error: {e}")
        return all_findings


_pipeline: DetectorPipeline | None = None


def get_detector_pipeline() -> DetectorPipeline:
    global _pipeline
    if _pipeline is None:
        try:
            _pipeline = DetectorPipeline()
        except Exception as e:
            print(f"[DetectorPipeline] init error: {e}")
            _pipeline = DetectorPipeline()
    return _pipeline
