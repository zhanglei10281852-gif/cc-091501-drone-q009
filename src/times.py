"""统一时间口径：对外一律带时区的 ISO 8601，内部以毫秒 epoch 比较先后。"""

from datetime import datetime
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Shanghai")


def now_ts() -> int:
    """当前 Asia/Shanghai 时间的毫秒 epoch。"""
    return int(datetime.now(tz=TZ).timestamp() * 1000)


def to_iso(ts_ms: int | None) -> str | None:
    if ts_ms is None:
        return None
    return datetime.fromtimestamp(ts_ms / 1000, tz=TZ).isoformat(timespec="milliseconds")


def parse_ts(value) -> int:
    """解析带时区的 ISO 8601 字符串；不接受无时区时间（各单位时间口径必须显式化）。"""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("time_required")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("time_invalid") from exc
    if dt.tzinfo is None:
        raise ValueError("time_timezone_required")
    return int(dt.timestamp() * 1000)
