"""
Pwntools Tool Implementation
CTF framework and exploit development
"""

from typing import Dict, List, Any
from ..base import BaseTool


class PwntoolsTool(BaseTool):
    """
    Pwntools - CTF framework and exploit development.
    
    Example usage:
        tool = PwntoolsTool()
        result = tool.execute('/path/to/binary', {
            'script': "from pwn import *; print(ELF('./binary').checksec())"
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Pwntools", "python3")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-c']
        
        script = params.get('script', '')
        if script:
            cmd.append(script)
        else:
            cmd.append(f"from pwn import *; print(ELF('{target}').checksec())")
        
        return cmd
