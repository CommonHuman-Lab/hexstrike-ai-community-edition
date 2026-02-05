"""
Wfuzz Tool Implementation
Web fuzzer
"""

from typing import Dict, List, Any
from ..base import BaseTool


class WfuzzTool(BaseTool):
    """
    Wfuzz - Web fuzzer.
    
    Example usage:
        tool = WfuzzTool()
        result = tool.execute('https://example.com/FUZZ', {
            'wordlist': '/usr/share/wordlists/common.txt'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Wfuzz", "wfuzz")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        wordlist = params.get('wordlist', '/usr/share/wordlists/common.txt')
        cmd.extend(['-w', wordlist])
        
        hide_codes = params.get('hide_codes', '')
        if hide_codes:
            cmd.extend(['--hc', hide_codes])
        
        hide_chars = params.get('hide_chars', '')
        if hide_chars:
            cmd.extend(['--hh', hide_chars])
        
        cmd.append(target)
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
