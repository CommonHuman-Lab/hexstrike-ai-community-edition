"""
SMBMap Tool Implementation
SMB share enumeration
"""

from typing import Dict, List, Any
from ..base import BaseTool


class SmbmapTool(BaseTool):
    """
    SMBMap - SMB share enumeration.
    
    Example usage:
        tool = SmbmapTool()
        result = tool.execute('192.168.1.100', {
            'username': 'guest',
            'password': ''
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("SMBMap", "smbmap")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-H', target]
        
        username = params.get('username', '')
        if username:
            cmd.extend(['-u', username])
        
        password = params.get('password', '')
        if password:
            cmd.extend(['-p', password])
        
        domain = params.get('domain', '')
        if domain:
            cmd.extend(['-d', domain])
        
        recursive = params.get('recursive', False)
        if recursive:
            cmd.append('-R')
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
