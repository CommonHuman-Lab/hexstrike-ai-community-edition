"""
Bug Bounty Agents Module
Specialized agents for bug bounty hunting operations
"""

from .workflow_manager import BugBountyTarget, BugBountyWorkflowManager

__all__ = ["BugBountyWorkflowManager", "BugBountyTarget"]
