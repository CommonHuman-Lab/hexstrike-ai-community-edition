"""
One-Gadget Tool Implementation
Find one-shot RCE gadgets in libc
"""

from typing import Dict, List, Any
from ..base import BaseTool


class OneGadgetTool(BaseTool):
    """
    One-Gadget - Find one-shot RCE gadgets in libc.
    
    Example usage:
        tool = OneGadgetTool()
        result = tool.execute('/lib/x86_64-linux-gnu/libc.so.6', {
            'level': 1
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("One Gadget", "one_gadget")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, target]
        
        level = params.get('level', '')
        if level:
            cmd.extend(['--level', str(level)])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
