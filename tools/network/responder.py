"""
Responder Tool Implementation
LLMNR/NBT-NS/MDNS poisoner
"""

from typing import Dict, List, Any
from ..base import BaseTool


class ResponderTool(BaseTool):
    """
    Responder - LLMNR/NBT-NS/MDNS poisoner.
    
    Example usage:
        tool = ResponderTool()
        result = tool.execute('', {
            'interface': 'eth0',
            'analyze': True
        }, execute_command)
    """
    
    def __init__(self):
        super().__init__("Responder", "responder")
    
    def build_command(self, target: str, params: Dict[str, Any]) -> List[str]:
        cmd = [self.binary_name]
        
        interface = params.get('interface', 'eth0')
        cmd.extend(['-I', interface])
        
        analyze = params.get('analyze', False)
        if analyze:
            cmd.append('-A')
        
        additional_args = params.get('additional_args', '')
        if additional_args:
            cmd.extend(additional_args.split())
        
        return cmd
