"""
Sigma rule support (single-event rules).

Supported:
  * detection selections as maps (fields AND-ed, list values OR-ed) or lists
    of maps (OR), plus keyword lists (searched in message/raw_message)
  * modifiers: contains, startswith, endswith, re, cidr, all, gt/gte/lt/lte
  * conditions with and / or / not / parentheses, `1 of sel*`, `all of sel*`,
    `1 of them`, `all of them`
  * Sigma field names mapped to ours (Image, CommandLine, ParentImage, User,
    DestinationIp, QueryName, c-uri, ...)

Not supported (rule is skipped with a load error, never silently mis-run):
  aggregation conditions (`| count() > 5`) and `near` - use the YAML rule
  engine's `threshold:` for those.

Replaces a stub that ignored the `condition` entirely and compared raw field
names (e.g. "CommandLine") that never exist in normalized events.
"""
import fnmatch
import re
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

import yaml

from src.detection.rules.custom_rules import SEVERITIES, _matched_fields
from src.detection.rules.matcher import compile_condition

FIELD_MAP = {
    "image": "process_path", "commandline": "command_line", "parentimage": "parent_process",
    "parentcommandline": "parent_command_line", "originalfilename": "process_name", "user": "user",
    "destinationip": "dst_ip", "destinationport": "dst_port", "sourceip": "src_ip", "sourceport": "src_port",
    "destinationhostname": "dst_host", "queryname": "query", "targetfilename": "file_path", "hashes": "file_hash",
    "computername": "hostname", "c-ip": "src_ip", "c-uri": "url", "cs-uri-query": "url", "cs-uri-stem": "url",
    "cs-method": "http_method", "sc-status": "status_code", "c-useragent": "user_agent",
    "eventid": "event_code", "logontype": "logon_type",
}
LEVELS = {"informational": "low", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}
_TOKEN = re.compile(r"\(|\)|\b(?:and|or|not)\b|\b(?:1|all) of [\w*]+|[\w*\-]+", re.IGNORECASE)


def _field(name: str) -> str:
    return FIELD_MAP.get(name.lower(), name.lower())


def _get(event: Dict[str, Any], field: str):
    value = event.get(field)
    if value is None and field == "process_path":
        return event.get("process_name")  # Image|endswith: '\\certutil.exe' still works on bare names
    return value


def _compile_selection(selection: Any) -> Callable[[Dict[str, Any]], bool]:
    if isinstance(selection, dict):
        preds = []
        for key, value in selection.items():
            field, *mods = key.split("|")
            mods = [m.lower() for m in mods]
            if "windash" in mods or "base64" in mods or "base64offset" in mods:
                raise ValueError(f"modifier {mods} not supported")
            preds.append(compile_condition("|".join([_field(field), *mods]), value, _get))
        return lambda e: all(p(e) for p in preds)
    if isinstance(selection, list) and selection and all(isinstance(s, dict) for s in selection):
        subs = [_compile_selection(s) for s in selection]
        return lambda e: any(p(e) for p in subs)
    if isinstance(selection, list):  # keywords
        words = [str(w).lower() for w in selection]
        return lambda e: any(w in str(e.get("message") or e.get("raw_message") or e.get("command_line") or
                                      "").lower() for w in words)
    raise ValueError("unsupported selection")


class _ConditionParser:
    def __init__(self, text: str, selections: Dict[str, Callable]):
        if "|" in text or " near " in f" {text} ":
            raise ValueError("aggregation/near conditions are not supported")
        self.tokens = _TOKEN.findall(text)
        self.pos = 0
        self.sel = selections

    def parse(self) -> Callable:
        expr = self._or()
        if self.pos != len(self.tokens):
            raise ValueError(f"unexpected token {self.tokens[self.pos]!r}")
        return expr

    def _peek(self):
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _take(self):
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def _or(self):
        left = self._and()
        while self._peek() == "or":
            self._take()
            right = self._and()
            left = (lambda a, b: lambda e: a(e) or b(e))(left, right)
        return left

    def _and(self):
        left = self._not()
        while self._peek() == "and":
            self._take()
            right = self._not()
            left = (lambda a, b: lambda e: a(e) and b(e))(left, right)
        return left

    def _not(self):
        if self._peek() == "not":
            self._take()
            inner = self._not()
            return lambda e: not inner(e)
        return self._atom()

    def _atom(self):
        tok = self._take()
        low = tok.lower()
        if low == "(":
            expr = self._or()
            if self._take() != ")":
                raise ValueError("missing )")
            return expr
        if low.startswith(("1 of ", "all of ")):
            quant, pattern = low.split(" of ")
            names = list(self.sel) if pattern == "them" else [n for n in self.sel if fnmatch.fnmatch(n, pattern)]
            if not names:
                raise ValueError(f"no selection matches {pattern}")
            preds = [self.sel[n] for n in names]
            return (lambda e: any(p(e) for p in preds)) if quant == "1" else (lambda e: all(p(e) for p in preds))
        if tok not in self.sel:
            raise ValueError(f"unknown selection {tok!r}")
        return self.sel[tok]


class SigmaRule:
    source = "sigma"

    def __init__(self, data: Dict[str, Any], path: str = ""):
        detection = dict(data.get("detection") or {})
        condition = detection.pop("condition", None)
        if not condition:
            raise ValueError("missing detection.condition")
        if isinstance(condition, list):
            condition = " or ".join(f"({c})" for c in condition)
        detection.pop("timeframe", None)
        selections = {name: _compile_selection(sel) for name, sel in detection.items()}
        self._predicate = _ConditionParser(str(condition), selections).parse()

        self.id = str(data.get("id") or Path(path).stem)
        self.name = data.get("title", self.id)
        self.description = data.get("description", "")
        self.severity = LEVELS.get(str(data.get("level", "medium")).lower(), "medium")
        tags = [str(t).lower() for t in data.get("tags", []) or []]
        self.mitre = [t.split(".", 1)[1].upper() for t in tags if re.match(r"attack\.t\d{4}", t)]
        tactics = [t.split(".", 1)[1] for t in tags if t.startswith("attack.") and not re.match(r"attack\.t\d", t)]
        self.category = (data.get("category") or (tactics[0] if tactics else "sigma")).replace("-", "_")
        self.enabled = str(data.get("status", "")).lower() != "deprecated"
        self.confidence = 0.75
        self.response = list(data.get("response", []) or [])
        self.cooldown = 600.0
        self.references = list(data.get("references", []) or [])
        self.group_by = ["src_ip", "hostname"]
        self.threshold = None
        self.hits = 0
        self.path = path
        assert self.severity in SEVERITIES

    def meta(self) -> Dict[str, Any]:
        return {"rule_id": self.id, "rule_name": self.name, "description": self.description,
                "severity": self.severity, "category": self.category, "mitre": self.mitre,
                "confidence": self.confidence, "response": self.response, "source": self.source,
                "cooldown": self.cooldown, "references": self.references}

    def summary(self) -> Dict[str, Any]:
        out = {k: v for k, v in self.meta().items() if k != "cooldown"}
        out.update(enabled=self.enabled, hits=self.hits, threshold=None, group_by=self.group_by)
        return out

    def evaluate(self, event: Dict[str, Any]):
        if not self.enabled or not self._predicate(event):
            return None
        self.hits += 1
        group = {f: event.get(f) for f in self.group_by}
        return {**self.meta(), "group": group, "group_key": "|".join(str(v) for v in group.values()),
                "count": 1, "events": [event], "evidence": {"matched": _matched_fields(event)}}


def load_sigma_rules(directories: List[Path]) -> Tuple[List[SigmaRule], List[str]]:
    rules, errors = [], []
    for directory in directories:
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.y*ml")):
            try:
                for doc in yaml.safe_load_all(path.read_text(encoding="utf-8-sig")):
                    if doc:
                        rules.append(SigmaRule(doc, str(path)))
            except Exception as e:
                errors.append(f"sigma {path.name}: {e}")
    return rules, errors
