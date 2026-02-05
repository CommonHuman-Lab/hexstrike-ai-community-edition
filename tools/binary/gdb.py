"""
GDB Tool Implementation
GNU Debugger
"""

from typing import Dict, List, Any
from ..base import BaseTool


class GdbTool(BaseTool):
    """
    GDB - GNU Debugger.
    
    Example usage:
        tool = GdbTool()
        result = tool.execute('/path/to/binary', {
            'commands': 'info functions'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("GDB", "gdb")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-q', '-batch']
        
        commands = params.get('commands', 'info functions')
        cmd.extend(['-ex', commands])
        
        cmd.append(target)
        return cmd
