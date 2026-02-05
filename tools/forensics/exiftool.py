"""
ExifTool Tool Implementation
Metadata extraction tool
"""

from typing import Dict, List, Any
from ..base import BaseTool


class ExiftoolTool(BaseTool):
    """
    ExifTool - Metadata extraction tool.
    
    Example usage:
        tool = ExiftoolTool()
        result = tool.execute('/path/to/file.jpg', {
            'output_format': 'json'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("ExifTool", "exiftool")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        output_format = params.get('output_format', '')
        if output_format == 'json':
            cmd.append('-json')
        
        all_tags = params.get('all_tags', True)
        if all_tags:
            cmd.append('-a')
        
        verbose = params.get('verbose', False)
        if verbose:
            cmd.append('-v')
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        cmd.append(target)
        return cmd
