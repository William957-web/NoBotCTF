from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from zoneinfo import ZoneInfo

from .config import APP_TZ


LOCAL_TZ = ZoneInfo(APP_TZ)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_utc(dt: datetime | None = None) -> str:
    value = dt or utcnow()
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def parse_local_datetime(value: str) -> datetime:
    cleaned = value.strip()
    dt = datetime.strptime(cleaned, "%Y-%m-%dT%H:%M")
    return dt.replace(tzinfo=LOCAL_TZ).astimezone(timezone.utc)


def to_local_value(value: str | None) -> str:
    if not value:
        return ""
    return parse_iso(value).astimezone(LOCAL_TZ).strftime("%Y-%m-%dT%H:%M")


def display_time(value: str | None) -> str:
    if not value:
        return "-"
    return parse_iso(value).astimezone(LOCAL_TZ).strftime("%Y-%m-%d %H:%M")


def display_duration(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} min"
    hours, mins = divmod(minutes, 60)
    return f"{hours} hr {mins} min" if mins else f"{hours} hr"


def slugify(value: str, fallback: str = "item") -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or fallback


def clip(value: str, limit: int) -> str:
    value = value.strip()
    return value if len(value) <= limit else value[:limit]


def challenge_close_from(open_value: str, duration_minutes: int) -> str:
    opens_at = parse_local_datetime(open_value)
    return iso_utc(opens_at + timedelta(minutes=duration_minutes))
