from pydantic import BaseModel


class DailyStatsResponse(BaseModel):
    date: str
    total_detect: int
    total_mask: int
    type_distribution: dict[str, int]
