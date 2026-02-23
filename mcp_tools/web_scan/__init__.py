
from .nikto import register_nikto_tool
from .sqlmap import register_sqlmap_tool
from .wpscan import register_wpscan_tool
from .jaeles import register_jaeles_tool
from .dalfox import register_dalfox_tool
from .burpsuite import register_burpsuite_tool
from .zap import register_zap_tool
from .xsser import register_xsser_tool

__all__ = [
    "register_nikto_tool",
    "register_sqlmap_tool",
    "register_wpscan_tool",
    "register_jaeles_tool",
    "register_dalfox_tool",
    "register_burpsuite_tool",
    "register_zap_tool",
    "register_xsser_tool",
]