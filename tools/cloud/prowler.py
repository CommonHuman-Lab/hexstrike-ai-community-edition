"""
Prowler Tool Implementation
AWS/Azure/GCP security assessment
"""

from typing import Dict, List, Any
from ..base import BaseTool


class ProwlerTool(BaseTool):
    """
    Prowler - AWS/Azure/GCP security assessment.
    
    Example usage:
        tool = ProwlerTool()
        result = tool.execute('', {
            'provider': 'aws',
            'profile': 'default',
            'region': 'us-east-1'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Prowler", "prowler")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        provider = params.get('provider', 'aws')
        cmd.extend(['-M', provider])
        
        profile = params.get('profile', '')
        if profile:
            cmd.extend(['-p', profile])
        
        region = params.get('region', '')
        if region:
            cmd.extend(['-r', region])
        
        checks = params.get('checks', '')
        if checks:
            cmd.extend(['-c', checks])
        
        output_dir = params.get('output_dir', '/tmp/prowler_output')
        cmd.extend(['-o', output_dir])
        
        output_format = params.get('output_format', 'json')
        cmd.extend(['-F', output_format])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
