"""
GDB-PEDA Tool Implementation
GDB with Python Exploit Development Assistance
"""

from typing import Dict, List, Any
from ..base import BaseTool


class GdbPedaTool(BaseTool):
    """
    GDB-PEDA - GDB with Python Exploit Development Assistance.
    
    Example usage:
        tool = GdbPedaTool()
        result = tool.execute('/path/to/binary', {
            'commands': 'checksec'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("GDB-PEDA", "gdb")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-q']
        
        commands = params.get('commands', 'checksec')
        cmd.extend(['-ex', 'source ~/.gdbinit-gef.py || source ~/.gdbinit'])
        cmd.extend(['-ex', commands])
        cmd.extend(['-ex', 'quit'])
        
        cmd.append(target)
        
        return cmd
