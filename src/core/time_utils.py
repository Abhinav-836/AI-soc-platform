from datetime import datetime, timedelta
from typing import Union


class TimeUtils:
    """Utility functions for time operations."""
    
    @staticmethod
    def now() -> datetime:
        """Get current UTC time."""
        return datetime.utcnow()
    
    @staticmethod
    def timestamp() -> int:
        """Get current Unix timestamp."""
        return int(datetime.utcnow().timestamp())
    
    @staticmethod
    def parse(time_str: str) -> datetime:
        """Parse ISO format time string."""
        return datetime.fromisoformat(time_str.replace('Z', '+00:00'))
    
    @staticmethod
    def format(dt: datetime) -> str:
        """Format datetime to ISO string."""
        return dt.isoformat() + 'Z'
    
    @staticmethod
    def time_window(seconds: int) -> datetime:
        """Get datetime N seconds ago."""
        return datetime.utcnow() - timedelta(seconds=seconds)