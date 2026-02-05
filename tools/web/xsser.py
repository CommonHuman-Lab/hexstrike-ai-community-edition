"""
XSSer Tool Implementation
Cross-site scripting scanner
"""

from typing import Dict, List, Any
from ..base import BaseTool


class XsserTool(BaseTool):
    """
    XSSer - Cross-site scripting scanner.
    
    Example usage:
        tool = XsserTool()
        result = tool.execute('https://example.com/page?param=test', {
            'auto': True
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("XSSer", "xsser")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-u', target]
        
        auto = params.get('auto', True)
        if auto:
            cmd.append('--auto')
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
