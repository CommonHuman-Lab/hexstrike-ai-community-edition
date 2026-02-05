"""
Pacu Tool Implementation
AWS exploitation framework
"""

from typing import Dict, List, Any
from ..base import BaseTool


class PacuTool(BaseTool):
    """
    Pacu - AWS exploitation framework.
    
    Example usage:
        tool = PacuTool()
        result = tool.execute('', {
            'session': 'my_session',
            'module': 'iam__enum_users'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Pacu", "pacu")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        session = params.get('session', 'hexstrike')
        cmd.extend(['--session', session])
        
        module = params.get('module', '')
        if module:
            cmd.extend(['--module', module])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
