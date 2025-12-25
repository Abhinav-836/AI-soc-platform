import re
from typing import Dict, Any
from datetime import datetime

class CEFParser:
    """Parse CEF formatted logs."""
    
    CEF_REGEX = re.compile(
        r'CEF:(?P<version>\d+)\|(?P<device_vendor>[^|]*)\|(?P<device_product>[^|]*)\|'
        r'(?P<device_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|'
        r'(?P<severity>[^|]*)\|(?P<extension>.*)'
    )
    
    @staticmethod
    def parse(raw_log: str) -> Dict[str, Any]:
        """Parse CEF log entry."""
        match = CEFParser.CEF_REGEX.match(raw_log)
        
        if not match:
            return {
                "raw": raw_log,
                "parse_error": True,
                "parser": "cef"
            }
        
        parsed = match.groupdict()
        
        # Parse extension fields
        extension = parsed.pop('extension', '')
        ext_fields = CEFParser._parse_extension(extension)
        parsed.update(ext_fields)
        
        # Normalize
        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "cef_version": parsed.get('version'),
            "device_vendor": parsed.get('device_vendor'),
            "device_product": parsed.get('device_product'),
            "signature_id": parsed.get('signature_id'),
            "event_name": parsed.get('name'),
            "severity": CEFParser._map_severity(parsed.get('severity')),
            "source_ip": ext_fields.get('src'),
            "dest_ip": ext_fields.get('dst'),
            "source_port": ext_fields.get('spt'),
            "dest_port": ext_fields.get('dpt'),
            "protocol": ext_fields.get('proto'),
            "raw_data": raw_log
        }
    
    @staticmethod
    def _parse_extension(extension: str) -> Dict[str, str]:
        """Parse CEF extension fields."""
        fields = {}
        # Simple key=value parsing
        parts = extension.split(' ')
        for part in parts:
            if '=' in part:
                key, value = part.split('=', 1)
                fields[key] = value
        return fields
    
    @staticmethod
    def _map_severity(cef_severity: str) -> str:
        """Map CEF severity to standard levels."""
        try:
            level = int(cef_severity)
            if level >= 8:
                return "CRITICAL"
            elif level >= 6:
                return "HIGH"
            elif level >= 4:
                return "MEDIUM"
            elif level >= 2:
                return "LOW"
            else:
                return "INFO"
        except (ValueError, TypeError):
            return "INFO"