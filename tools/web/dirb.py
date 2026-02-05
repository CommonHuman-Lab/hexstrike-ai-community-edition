"""
Dirb Tool Implementation
Web content scanner
"""

from typing import Dict, List, Any
from ..base import BaseTool


class DirbTool(BaseTool):
    """
    Dirb - Web content scanner.
    
    Example usage:
        tool = DirbTool()
        result = tool.execute('https://example.com', {
            'wordlist': '/usr/share/dirb/wordlists/common.txt'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Dirb", "dirb")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, target]
        
        wordlist = params.get('wordlist', '/usr/share/dirb/wordlists/common.txt')
        cmd.append(wordlist)
        
        extensions = params.get('extensions', '')
        if extensions:
            cmd.extend(['-X', extensions])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
