# Global configuration for HexStrike AI Community Edition

from typing import Any, Optional

_config = {
    "APP_NAME": "HexStrike AI Community Edition",
    "VERSION": "1.0.3",
    "COMMAND_TIMEOUT": 300
}

def get(key: str, default: Optional[Any] = None) -> Any:
    """Get a configuration value by key."""
    return _config.get(key, default)

def set(key: str, value: Any) -> None:
    """Set a configuration value by key."""
    _config[key] = value