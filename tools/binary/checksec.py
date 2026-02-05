"""
Checksec Tool Implementation
Binary security property checker
"""

from typing import Dict, List, Any
from ..base import BaseTool


class ChecksecTool(BaseTool):
    """
    Checksec - Binary security property checker.
    
    Example usage:
        tool = ChecksecTool()
        result = tool.execute('/path/to/binary', {
            'output_format': 'json'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Checksec", "checksec")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '--file', target]
        
        output_format = params.get('output_format', '')
        if output_format:
            cmd.extend(['--output', output_format])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
