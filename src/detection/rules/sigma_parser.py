import yaml
from typing import Dict, Any, List
from pathlib import Path

class SigmaRule:
    """Sigma detection rule."""
    
    def __init__(self, rule_data: Dict[str, Any]):
        self.id = rule_data.get('id')
        self.title = rule_data.get('title')
        self.description = rule_data.get('description')
        self.level = rule_data.get('level', 'medium')
        self.detection = rule_data.get('detection', {})
        self.tags = rule_data.get('tags', [])
    
    def matches(self, event: Dict[str, Any]) -> bool:
        """Check if event matches Sigma rule."""
        selection = self.detection.get('selection', {})
        condition = self.detection.get('condition', '')
        
        # Simple matching logic (production would be more complex)
        for field, expected in selection.items():
            event_value = event.get(field)
            
            if isinstance(expected, list):
                if event_value not in expected:
                    return False
            else:
                if event_value != expected:
                    return False
        
        return True

class SigmaParser:
    """Parse and manage Sigma rules."""
    
    def __init__(self, rules_dir: str = "config/detection/rules/sigma"):
        self.rules_dir = Path(rules_dir)
        self.rules = []
    
    def load_rules(self) -> List[SigmaRule]:
        """Load all Sigma rules from directory."""
        if not self.rules_dir.exists():
            return []
        
        for rule_file in self.rules_dir.glob("*.yml"):
            try:
                with open(rule_file, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    self.rules.append(SigmaRule(rule_data))
            except Exception as e:
                print(f"Failed to load rule {rule_file}: {e}")
        
        return self.rules