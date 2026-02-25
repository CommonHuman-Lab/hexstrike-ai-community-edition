from .hydra import *
from .john import *
from .hashcat import *
from .medusa import *
from .patator import *
from .hashid import *
from .ophcrack import *
from .aircrack_ng import *

__all__ = [
    "register_hydra_tool", 
    "register_john_tool", 
    "register_hashcat_tool",
    "register_medusa_tool",
    "register_patator_tool",
    "register_hashid_tool",
    "register_ophcrack_tool",
    "register_aircrack_ng_tools"
]