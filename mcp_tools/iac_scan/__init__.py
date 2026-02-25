from .checkov import register_checkov_tool
from .terrascan import register_terrascan_tool

__all__ = [
    'register_checkov_tool',
    'register_terrascan_tool'
]