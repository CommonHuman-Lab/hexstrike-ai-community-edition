"""
Enum4linux-ng Tool Implementation
Modern SMB enumeration tool
"""

from typing import Dict, List, Any
from ..base import BaseTool


class Enum4linuxNgTool(BaseTool):
    """
    Enum4linux-ng - Modern SMB enumeration tool.
    
    Example usage:
        tool = Enum4linuxNgTool()
        result = tool.execute('192.168.1.100', {
            'all': True
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Enum4linux-ng", "enum4linux-ng")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        all_enum = params.get('all', True)
        if all_enum:
            cmd.append('-A')
        
        username = params.get('username', '')
        if username:
            cmd.extend(['-u', username])
        
        password = params.get('password', '')
        if password:
            cmd.extend(['-p', password])
        
        output_format = params.get('output_format', '')
        if output_format:
            cmd.extend(['-oJ', output_format])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        cmd.append(target)
        return cmd
