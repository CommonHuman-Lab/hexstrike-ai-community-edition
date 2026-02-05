"""
Objdump Tool Implementation
Object file disassembler
"""

from typing import Dict, List, Any
from ..base import BaseTool


class ObjdumpTool(BaseTool):
    """
    Objdump - Object file disassembler.
    
    Example usage:
        tool = ObjdumpTool()
        result = tool.execute('/path/to/binary', {
            'disassemble': True
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Objdump", "objdump")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        disassemble = params.get('disassemble', True)
        if disassemble:
            cmd.append('-d')
        
        headers = params.get('headers', False)
        if headers:
            cmd.append('-h')
        
        symbols = params.get('symbols', False)
        if symbols:
            cmd.append('-t')
        
        cmd.append(target)
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
