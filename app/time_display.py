from __future__ import annotations

from datetime import datetime, timedelta, timezone


SINGAPORE_TZ = timezone(timedelta(hours=8), name="SGT")


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def utc_iso(value: datetime | None) -> str:
    if value is None:
        return ""
    return as_utc(value).isoformat()


def sgt_datetime(value: datetime | None) -> str:
    if value is None:
        return ""
    return as_utc(value).astimezone(SINGAPORE_TZ).strftime("%d %b %Y, %H:%M:%S SGT")


def to_singapore_time(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return as_utc(value).astimezone(SINGAPORE_TZ)


def sgt_date(value: datetime | None) -> str:
    if value is None:
        return ""
    return as_utc(value).astimezone(SINGAPORE_TZ).strftime("%d %b %Y")


def sgt_time(value: datetime | None) -> str:
    if value is None:
        return ""
    localized = as_utc(value).astimezone(SINGAPORE_TZ)
    hour_12 = localized.strftime("%I").lstrip("0") or "12"
    return f"{hour_12}:{localized.strftime('%M %p')} SGT"
