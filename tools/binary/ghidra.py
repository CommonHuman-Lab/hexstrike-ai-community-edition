"""
Ghidra Tool Implementation
Software reverse engineering suite
"""

from typing import Dict, List, Any
from ..base import BaseTool


class GhidraTool(BaseTool):
    """
    Ghidra - Software reverse engineering suite.
    
    Example usage:
        tool = GhidraTool()
        result = tool.execute('/path/to/binary', {
            'project_dir': '/tmp/ghidra',
            'project_name': 'analysis'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Ghidra", "analyzeHeadless")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        project_dir = params.get('project_dir', '/tmp/ghidra_projects')
        cmd.append(project_dir)
        
        project_name = params.get('project_name', 'hexstrike_analysis')
        cmd.append(project_name)
        
        cmd.extend(['-import', target])
        
        script = params.get('script', '')
        if script:
            cmd.extend(['-scriptPath', script])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
