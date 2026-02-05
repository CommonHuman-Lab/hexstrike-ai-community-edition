"""
GraphQL Scanner Tool Implementation
GraphQL vulnerability scanning
"""

from typing import Dict, List, Any
from ..base import BaseTool


class GraphqlScannerTool(BaseTool):
    """
    GraphQL Scanner - GraphQL vulnerability scanning.
    
    Example usage:
        tool = GraphqlScannerTool()
        result = tool.execute('https://api.example.com/graphql', {
            'introspection': True
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("GraphQL Scanner", "graphw00f")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name, '-t', target]
        
        fingerprint = params.get('fingerprint', True)
        if fingerprint:
            cmd.append('-f')
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
