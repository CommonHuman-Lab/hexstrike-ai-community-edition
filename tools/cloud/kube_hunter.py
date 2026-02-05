"""
Kube-hunter Tool Implementation
Kubernetes penetration testing
"""

from typing import Dict, List, Any
from ..base import BaseTool


class KubeHunterTool(BaseTool):
    """
    Kube-hunter - Kubernetes penetration testing.
    
    Example usage:
        tool = KubeHunterTool()
        result = tool.execute('192.168.1.100', {
            'active': True,
            'report': 'json'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Kube Hunter", "kube-hunter")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        remote = params.get('remote', '')
        if remote:
            cmd.extend(['--remote', remote])
        elif target:
            cmd.extend(['--remote', target])
        
        cidr = params.get('cidr', '')
        if cidr:
            cmd.extend(['--cidr', cidr])
        
        active = params.get('active', False)
        if active:
            cmd.append('--active')
        
        report = params.get('report', 'json')
        cmd.extend(['--report', report])
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
