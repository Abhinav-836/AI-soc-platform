"""
Time helpers. Everything is timezone-aware UTC.

The old code mixed datetime.utcnow() (naive) with parsed "...Z" timestamps
(aware); every comparison raised "can't compare offset-naive and
offset-aware datetimes", which is why correlation never produced an alert.
"""
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

_WINDOW = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([smhd]?)\s*$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "": 60}
_FORMATS = ("%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%b %d %H:%M:%S", "%Y/%m/%d %H:%M:%S")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_ts(value: Any, default: Optional[datetime] = None) -> Optional[datetime]:
    """Parse ISO strings, epoch seconds/ms and common log formats into aware UTC."""
    if value is None or value == "":
        return default
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    text = str(value).strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _FORMATS:
        try:
            if fmt == "%b %d %H:%M:%S":  # syslog timestamps have no year
                now = utcnow()
                dt = datetime.strptime(f"{now.year} {text}", f"%Y {fmt}").replace(tzinfo=timezone.utc)
                if dt > now + timedelta(days=1):  # "Dec 31" read in early January
                    dt = dt.replace(year=now.year - 1)
                return dt
            dt = datetime.strptime(text, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return default


def parse_window(value: Any, default: float = 300.0) -> float:
    """'5m' -> 300.0 seconds. Bare numbers are minutes (backwards compatible)."""
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value) * 60
    m = _WINDOW.match(str(value))
    if not m:
        return default
    return float(m.group(1)) * _UNITS[m.group(2)]


class TimeUtils:
    """Backwards-compatible facade."""
    now = staticmethod(utcnow)
    parse = staticmethod(parse_ts)
    format = staticmethod(iso)

    @staticmethod
    def timestamp() -> int:
        return int(utcnow().timestamp())

    @staticmethod
    def time_window(seconds: int) -> datetime:
        return utcnow() - timedelta(seconds=seconds)
