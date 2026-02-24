from .hydra import register_hydra_tool
from .john import register_john_tool
from .hashcat import register_hashcat_tool
from .medusa import register_medusa_tool
from .patator import register_patator_tool
from .hashid import register_hashid_tool
from .ophcrack import register_ophcrack_tool

__all__ = [
    "register_hydra_tool", 
    "register_john_tool", 
    "register_hashcat_tool",
    "register_medusa_tool",
    "register_patator_tool",
    "register_hashid_tool",
    "register_ophcrack_tool"
]