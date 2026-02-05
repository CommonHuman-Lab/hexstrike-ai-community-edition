"""
Volatility3 Tool Implementation
Memory forensics framework
"""

from typing import Dict, List, Any
from ..base import BaseTool


class Volatility3Tool(BaseTool):
    """
    Volatility3 - Memory forensics framework.
    
    Example usage:
        tool = Volatility3Tool()
        result = tool.execute('/path/to/memory.dmp', {
            'plugin': 'windows.pslist'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Volatility3", "vol")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-f', target]
        
        plugin = params.get('plugin', 'windows.info')
        cmd.append(plugin)
        
        output_format = params.get('output_format', '')
        if output_format:
            cmd.extend(['-r', output_format])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
