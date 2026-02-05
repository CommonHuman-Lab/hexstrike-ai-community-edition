"""
Terrascan Tool Implementation
Infrastructure as code security scanner
"""

from typing import Dict, List, Any
from ..base import BaseTool


class TerrascanTool(BaseTool):
    """
    Terrascan - Infrastructure as code security scanner.
    
    Example usage:
        tool = TerrascanTool()
        result = tool.execute('.', {
            'iac_type': 'terraform',
            'output': 'json'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Terrascan", "terrascan")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, 'scan']
        
        iac_type = params.get('iac_type', 'all')
        cmd.extend(['-t', iac_type])
        
        iac_dir = params.get('iac_dir', target or '.')
        cmd.extend(['-d', iac_dir])
        
        output = params.get('output', 'json')
        cmd.extend(['-o', output])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
