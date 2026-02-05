"""
Dotdotpwn Tool Implementation
Directory traversal fuzzer
"""

from typing import Dict, List, Any
from ..base import BaseTool


class DotdotpwnTool(BaseTool):
    """
    Dotdotpwn - Directory traversal fuzzer.
    
    Example usage:
        tool = DotdotpwnTool()
        result = tool.execute('192.168.1.100', {
            'module': 'http',
            'depth': 5
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Dotdotpwn", "dotdotpwn")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        module = params.get('module', 'http')
        cmd.extend(['-m', module])
        
        cmd.extend(['-h', target])
        
        depth = params.get('depth', 5)
        cmd.extend(['-d', str(depth)])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
