"""
API Fuzzer Tool Implementation
REST API endpoint fuzzing
"""

from typing import Dict, List, Any
from ..base import BaseTool


class ApiFuzzerTool(BaseTool):
    """
    API Fuzzer - REST API endpoint fuzzing.
    
    Example usage:
        tool = ApiFuzzerTool()
        result = tool.execute('https://api.example.com', {
            'wordlist': '/usr/share/wordlists/api-endpoints.txt'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("API Fuzzer", "ffuf")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-u', f'{target}/FUZZ']
        
        wordlist = params.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
        cmd.extend(['-w', wordlist])
        
        method = params.get('method', 'GET')
        cmd.extend(['-X', method])
        
        headers = params.get('headers', {})
        for key, value in headers.items():
            cmd.extend(['-H', f'{key}: {value}'])
        
        match_codes = params.get('match_codes', '200,201,204,301,302,307,401,403')
        cmd.extend(['-mc', match_codes])
        
        output_format = params.get('output_format', 'json')
        cmd.extend(['-of', output_format])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
