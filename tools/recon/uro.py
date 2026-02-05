"""
Uro Tool Implementation
URL deduplication and reduction
"""

from typing import Dict, List, Any
from ..base import BaseTool


class UroTool(BaseTool):
    """
    Uro - URL deduplication and reduction.
    
    Example usage:
        tool = UroTool()
        result = tool.execute('', {
            'input_file': 'urls.txt'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Uro", "uro")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        input_file = params.get('input_file', '')
        if input_file:
            cmd.extend(['-i', input_file])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
