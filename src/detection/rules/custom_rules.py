"""
Custom rule engine for detection.
"""

import re
import yaml
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta

from src.utils.logger import LoggerMixin


class Rule:
    """Represents a detection rule."""

    def __init__(self, rule_config: Dict[str, Any]):
        self.id = rule_config.get("id")
        self.name = rule_config.get("name")
        self.description = rule_config.get("description", "")
        self.severity = rule_config.get("severity", "medium")
        self.category = rule_config.get("category", "unknown")
        self.condition = rule_config.get("condition", "")
        self.actions = rule_config.get("actions", [])
        self.enabled = rule_config.get("enabled", True)

        # Compile condition
        self.compiled_condition = self._compile_condition(self.condition)

    def _compile_condition(self, condition: str) -> Callable[[Dict[str, Any]], bool]:
        """Compile condition string into function."""
        # Simple condition compilation
        # In production, use a proper expression evaluator
        def condition_func(event: Dict[str, Any]) -> bool:
            try:
                # Simple equality check for demo
                if "==" in condition:
                    left, right = condition.split("==", 1)
                    left = left.strip()
                    right = right.strip().strip('"').strip("'")

                    # Get value from event
                    value = event.get(left, "")
                    return str(value) == right

                # Regex match
                elif "matches" in condition:
                    field, pattern = condition.split("matches", 1)
                    field = field.strip()
                    pattern = pattern.strip().strip('"').strip("'")

                    value = str(event.get(field, ""))
                    return bool(re.match(pattern, value))

                # Custom logic would go here
                return False

            except Exception:
                return False

        return condition_func

    def evaluate(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluate rule against event."""
        if not self.enabled:
            return None

        try:
            if self.compiled_condition(event):
                return {
                    "rule_id": self.id,
                    "rule_name": self.name,
                    "description": self.description,
                    "severity": self.severity,
                    "category": self.category,
                    "confidence": 0.8,  # Default confidence
                    "indicators": self._extract_indicators(event),
                }
        except Exception as e:
            print(f"Error evaluating rule {self.id}: {e}")

        return None

    def _extract_indicators(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract IOCs from event."""
        indicators = []

        # Extract IPs
        for field in ["src_ip", "dst_ip", "client_ip"]:
            if field in event:
                indicators.append({
                    "type": "ip",
                    "value": event[field],
                    "field": field,
                })

        # Extract domains
        for field in ["domain", "hostname"]:
            if field in event:
                indicators.append({
                    "type": "domain",
                    "value": event[field],
                    "field": field,
                })

        return indicators


class RuleEngine(LoggerMixin):
    """Manages and evaluates detection rules."""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.rules: List[Rule] = []
        self.stats = {
            "rules_loaded": 0,
            "rules_evaluated": 0,
            "rules_failed": 0,
        }

    async def load_rules(self):
        """Load rules from configuration."""
        self.logger.info("Loading detection rules...")

        config = self.config.get("detection", {}).get("rules", {})

        # Load custom rules
        if config.get("custom", {}).get("enabled", False):
            custom_rules = config["custom"].get("rules", [])
            await self._load_custom_rules(custom_rules)

        # Load Sigma rules (if enabled)
        if config.get("sigma", {}).get("enabled", False):
            await self._load_sigma_rules(config["sigma"])

        # Load YARA rules (if enabled)
        if config.get("yara", {}).get("enabled", False):
            await self._load_yara_rules(config["yara"])

        self.logger.info(f"Loaded {len(self.rules)} detection rules")

    async def _load_custom_rules(self, rules_config: List[Dict[str, Any]]):
        """Load custom rules."""
        for rule_config in rules_config:
            try:
                rule = Rule(rule_config)
                self.rules.append(rule)
                self.stats["rules_loaded"] += 1
            except Exception as e:
                self.logger.error(f"Error loading rule: {e}", exc_info=True)
                self.stats["rules_failed"] += 1

    async def _load_sigma_rules(self, sigma_config: Dict[str, Any]):
        """Load Sigma rules."""
        # TODO: Implement Sigma rule loading
        # This would parse Sigma YAML files and convert to internal format
        self.logger.info("Sigma rule loading not yet implemented")

    async def _load_yara_rules(self, yara_config: Dict[str, Any]):
        """Load YARA rules."""
        # TODO: Implement YARA rule loading
        self.logger.info("YARA rule loading not yet implemented")

    async def evaluate(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Evaluate all rules against event."""
        matches = []

        for rule in self.rules:
            try:
                match = rule.evaluate(event)
                if match:
                    matches.append(match)

                self.stats["rules_evaluated"] += 1

            except Exception as e:
                self.logger.error(f"Error evaluating rule {rule.id}: {e}", exc_info=True)
                self.stats["rules_failed"] += 1

        return matches

    def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get rule by ID."""
        for rule in self.rules:
            if rule.id == rule_id:
                return rule
        return None

    def enable_rule(self, rule_id: str, enabled: bool = True):
        """Enable/disable a rule."""
        rule = self.get_rule(rule_id)
        if rule:
            rule.enabled = enabled

    def add_rule(self, rule_config: Dict[str, Any]):
        """Add a new rule."""
        try:
            rule = Rule(rule_config)
            self.rules.append(rule)
            self.stats["rules_loaded"] += 1
            return True
        except Exception as e:
            self.logger.error(f"Error adding rule: {e}", exc_info=True)
            return False

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule."""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                del self.rules[i]
                return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get rule engine statistics."""
        return {
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules if r.enabled),
            **self.stats,
        }

    def get_rules_summary(self) -> List[Dict[str, Any]]:
        """Get summary of all rules."""
        return [
            {
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity,
                "category": rule.category,
                "enabled": rule.enabled,
            }
            for rule in self.rules
        ]