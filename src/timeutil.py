"""时间口径：对外、落库统一为带时区的 ISO 8601（Asia/Shanghai）。

不同单位上报的采集时间各自保留原值，只做格式归一化，不用接收时间覆盖采集时间。
"""

from datetime import datetime
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Shanghai")


def now() -> datetime:
    return datetime.now(TZ)


def now_iso() -> str:
    # 服务器时间戳用微秒精度，保证同一案件连续程序动作（认定 -> 补证 -> 补交）严格先后可辨
    return format_dt(now(), force_microseconds=True)


def format_dt(dt: datetime, *, force_microseconds: bool = False) -> str:
    # 外部时间归一化保留原精度（微秒为 0 时不强制补 .000000）
    spec = "microseconds" if force_microseconds or dt.microsecond else "seconds"
    return dt.astimezone(TZ).isoformat(timespec=spec)


def parse_iso(value: str, field: str = "time") -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field} 必须是带时区的 ISO 8601 字符串")
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"{field} 不是合法的 ISO 8601 时间: {value}") from exc
    if dt.tzinfo is None:
        raise ValueError(f"{field} 必须携带时区偏移，禁止使用无时区时间: {value}")
    return dt.astimezone(TZ)


def normalize(value: str, field: str = "time") -> str:
    return format_dt(parse_iso(value, field))


def is_overdue(deadline: str, at: datetime | None = None) -> bool:
    return parse_iso(deadline, "deadline") <= (at or now())


def days_left(deadline: str, at: datetime | None = None) -> int:
    delta = parse_iso(deadline, "deadline") - (at or now())
    return int(delta.total_seconds() // 86400)
