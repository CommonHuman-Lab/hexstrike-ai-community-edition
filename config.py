# Global configuration for HexStrike AI Community Edition

from typing import Any, Optional

_config = {
    "APP_NAME": "HexStrike AI Community Edition",
    "VERSION": "1.0.7",
    "COMMAND_TIMEOUT": 300,
    "CACHE_SIZE": 1000,
    "CACHE_TTL": 3600,  # 1 hour
    "WORD_LISTS": {
        "rockyou": "/usr/share/wordlists/rockyou.txt", # This is a common password list used for brute-force attacks
        "common_dirb": "/usr/share/wordlists/dirb/common.txt",
        "common_dirsearch": "/usr/share/wordlists/dirsearch/common.txt",
    }
}

def get_word_list(name: str) -> Optional[str]:
    """Get the path to a word list by name."""
    return _config["WORD_LISTS"].get(name)

def get(key: str, default: Optional[Any] = None) -> Any:
    """Get a configuration value by key."""
    return _config.get(key, default)

def set(key: str, value: Any) -> None:
    """Set a configuration value by key."""
    _config[key] = value