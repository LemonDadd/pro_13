from app.utils.hash_utils import compute_value_hash


class Finding:
    def __init__(
        self,
        type: str,
        start: int,
        end: int,
        value: str,
        confidence: str = "med",
        field_path: str | None = None,
        is_whitelist: bool = False,
    ):
        self.type = type
        self.start = start
        self.end = end
        self.length = end - start
        self.value = value
        self.value_hash = compute_value_hash(value)
        self.confidence = confidence
        self.field_path = field_path
        self.is_whitelist = is_whitelist

    def to_dict(self, include_value: bool = False) -> dict:
        d = {
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "valueHash": self.value_hash,
            "confidence": self.confidence,
        }
        if self.field_path:
            d["fieldPath"] = self.field_path
        if include_value:
            d["value"] = self.value
        return d
