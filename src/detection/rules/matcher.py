"""
Field matching shared by the YAML rule engine and the Sigma loader.

A condition is written `field|modifier[|modifier...]: value`:

  event_type: ssh_failed                 equals (case-insensitive for text)
  event_type: [ssh_failed, rdp_failed]   any of the values
  url|contains: "../"                    substring
  url|startswith / |endswith
  command_line|re: "(?i)-enc\\s"         regular expression
  dst_ip|cidr: 10.0.0.0/8                IP inside network(s)
  dst_ip|private: false                  RFC1918/loopback/link-local or not
  bytes_out|gte: 1000000                 numeric comparisons: gt gte lt lte
  user|exists: true
  any modifier + |not                    negation
  values + |all                          every listed value must match (Sigma)
"""
import ipaddress
import re
from functools import lru_cache
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

_NUMERIC = {"gt": lambda a, b: a > b, "gte": lambda a, b: a >= b, "lt": lambda a, b: a < b,
            "lte": lambda a, b: a <= b}


@lru_cache(maxsize=4096)
def _network(value: str):
    return ipaddress.ip_network(value, strict=False)


@lru_cache(maxsize=65536)
def _ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


@lru_cache(maxsize=2048)
def _regex(pattern: str):
    return re.compile(pattern)


# "Internal" means RFC1918 / loopback / link-local / unique-local only.
# (ipaddress.is_private also treats documentation and other reserved ranges
# as private, which would make every simulated attacker look internal.)
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "100.64.0.0/10", "::1/128", "fc00::/7", "fe80::/10")]


def is_private_ip(value: Any) -> bool:
    ip = _ip(str(value)) if value is not None else None
    return bool(ip) and any(ip.version == n.version and ip in n for n in INTERNAL_NETWORKS)


def _as_number(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _single(actual: Any, op: str, expected: Any) -> bool:
    if op == "exists":
        return (actual not in (None, "")) == bool(expected)
    if actual is None:
        return False
    if op == "private":
        return is_private_ip(actual) == bool(expected)
    if op in ("cidr", "in_cidr"):
        ip = _ip(str(actual))
        return bool(ip) and any(ip in _network(str(n)) for n in _listify(expected))
    if op in _NUMERIC:
        a, b = _as_number(actual), _as_number(expected)
        return a is not None and b is not None and _NUMERIC[op](a, b)
    if op == "re":
        return bool(_regex(str(expected)).search(str(actual)))

    a, b = str(actual).lower(), str(expected).lower()
    if op in ("eq", "in", ""):
        if isinstance(actual, (int, float)) and _as_number(expected) is not None:
            return float(actual) == float(expected)
        return a == b
    if op == "contains":
        return b in a
    if op == "startswith":
        return a.startswith(b)
    if op == "endswith":
        return a.endswith(b)
    raise ValueError(f"Unknown modifier: {op}")


def _listify(value: Any) -> List[Any]:
    return list(value) if isinstance(value, (list, tuple, set)) else [value]


def parse_key(key: str) -> Tuple[str, List[str]]:
    field, *mods = key.split("|")
    return field, [m.strip().lower() for m in mods if m.strip()]


def compile_condition(key: str, expected: Any, getter: Callable[[Dict[str, Any], str], Any] = None):
    """Return predicate(event) for one `field|mods: value` entry."""
    field, mods = parse_key(key)
    negate = "not" in mods
    require_all = "all" in mods
    ops = [m for m in mods if m not in ("not", "all")] or ["eq"]
    op = ops[0]
    if op not in _NUMERIC and op not in ("eq", "in", "contains", "startswith", "endswith", "re", "cidr", "in_cidr",
                                          "private", "exists"):
        raise ValueError(f"Unknown modifier '{op}' in '{key}'")
    values = _listify(expected)
    get = getter or (lambda e, f: e.get(f))

    def predicate(event: Dict[str, Any]) -> bool:
        actual = get(event, field)
        actuals = actual if isinstance(actual, list) else [actual]
        hits = [any(_single(a, op, v) for a in actuals) for v in values]
        result = all(hits) if require_all else any(hits)
        return not result if negate else result

    return predicate


def compile_mapping(spec: Optional[Dict[str, Any]], getter=None) -> Callable[[Dict[str, Any]], bool]:
    """All conditions of a mapping must hold. Empty/None mapping matches everything."""
    preds = [compile_condition(k, v, getter) for k, v in (spec or {}).items()]
    return lambda event: all(p(event) for p in preds)


def compile_any(specs: Optional[Iterable[Dict[str, Any]]], getter=None) -> Optional[Callable[[Dict[str, Any]], bool]]:
    specs = list(specs or [])
    if not specs:
        return None
    preds = [compile_mapping(s, getter) for s in specs]
    return lambda event: any(p(event) for p in preds)
