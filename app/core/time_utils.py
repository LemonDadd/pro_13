from datetime import datetime, timezone, date


def utc_now() -> datetime:
    """返回 UTC aware 的当前 datetime"""
    return datetime.now(timezone.utc)


def utc_today() -> date:
    """返回 UTC 的当前 date"""
    return utc_now().date()


def utc_day_range(target_date: date) -> tuple[datetime, datetime]:
    """返回指定 UTC 日期的 00:00:00 ~ 23:59:59.999999 范围（UTC aware）"""
    start = datetime.combine(target_date, datetime.min.time(), tzinfo=timezone.utc)
    end = datetime.combine(target_date, datetime.max.time(), tzinfo=timezone.utc)
    return start, end
