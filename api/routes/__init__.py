"""
API Routes Module
Organized Flask blueprints for HexStrike API endpoints
"""

from .ai import ai_bp
from .bugbounty import bugbounty_bp
from .core import core_bp
from .ctf import ctf_bp
from .error_handling import error_handling_bp
from .files import files_bp
from .intelligence import intelligence_bp
from .knowledge_graph import knowledge_graph_bp
from .process_workflows import process_workflows_bp
from .processes import processes_bp
from .python_env import python_env_bp
from .scan_intelligence import scan_intelligence_bp
from .scan_memory import scan_memory_bp
from .tools_api import tools_api_bp
from .tools_binary import tools_binary_bp
from .tools_cloud import tools_cloud_bp
from .tools_exploit import tools_exploit_bp
from .tools_forensics import tools_forensics_bp
from .tools_network import tools_network_bp
from .tools_parameters import tools_parameters_bp
from .tools_recon import tools_recon_bp
from .tools_web import tools_web_bp
from .tools_web_advanced import tools_web_advanced_bp
from .tools_web_frameworks import tools_web_frameworks_bp
from .verification import verification_bp
from .visual import visual_bp
from .vuln_intel import vuln_intel_bp

__all__ = [
    "files_bp",
    "visual_bp",
    "error_handling_bp",
    "intelligence_bp",
    "processes_bp",
    "bugbounty_bp",
    "ctf_bp",
    "vuln_intel_bp",
    "core_bp",
    "ai_bp",
    "python_env_bp",
    "process_workflows_bp",
    "tools_cloud_bp",
    "tools_web_bp",
    "tools_web_advanced_bp",
    "tools_network_bp",
    "tools_exploit_bp",
    "tools_binary_bp",
    "tools_api_bp",
    "tools_parameters_bp",
    "tools_forensics_bp",
    "tools_web_frameworks_bp",
    "tools_recon_bp",
    "scan_intelligence_bp",
    "scan_memory_bp",
    "verification_bp",
    "knowledge_graph_bp",
]
