"""
ARP-Scan Tool Implementation
Network discovery using ARP
"""

from typing import Dict, List, Any
from ..base import BaseTool


class ArpScanTool(BaseTool):
    """
    ARP-Scan - Network discovery using ARP.
    
    Example usage:
        tool = ArpScanTool()
        result = tool.execute('192.168.1.0/24', {
            'interface': 'eth0'
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("ARP-Scan", "arp-scan")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        interface = params.get('interface', '')
        if interface:
            cmd.extend(['-I', interface])
        
        localnet = params.get('localnet', False)
        if localnet:
            cmd.append('-l')
        else:
            cmd.append(target)
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
