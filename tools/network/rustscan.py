"""
Rustscan Tool Implementation
Ultra-fast port scanner
"""

from typing import Dict, List, Any
from ..base import BaseTool


class RustscanTool(BaseTool):
    """
    Rustscan - Ultra-fast port scanner.
    
    Example usage:
        tool = RustscanTool()
        result = tool.execute('192.168.1.100', {
            'ports': '1-65535',
            'batch_size': '5000'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Rustscan", "rustscan")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-a', target]
        
        ports = params.get('ports', '')
        if ports:
            cmd.extend(['-p', ports])
        
        batch_size = params.get('batch_size', '')
        if batch_size:
            cmd.extend(['-b', str(batch_size)])
        
        timeout = params.get('timeout', '')
        if timeout:
            cmd.extend(['--timeout', str(timeout)])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
