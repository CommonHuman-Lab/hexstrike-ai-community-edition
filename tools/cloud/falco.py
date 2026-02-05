"""
Falco Tool Implementation
Runtime security monitoring
"""

from typing import Dict, List, Any
from ..base import BaseTool


class FalcoTool(BaseTool):
    """
    Falco - Runtime security monitoring.
    
    Example usage:
        tool = FalcoTool()
        result = tool.execute('', {
            'rules_file': '/etc/falco/falco_rules.yaml'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Falco", "falco")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        config = params.get('config', '/etc/falco/falco.yaml')
        cmd.extend(['-c', config])
        
        rules_file = params.get('rules_file', '')
        if rules_file:
            cmd.extend(['-r', rules_file])
        
        json_output = params.get('json_output', True)
        if json_output:
            cmd.extend(['-o', 'json_output=true'])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
