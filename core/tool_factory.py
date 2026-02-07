"""
HexStrike AI - Tool Factory Module

This module provides factory functions for creating tool executors.

Functions:
    - create_tool_executor: Factory function to create tool executor from tool class
"""

from typing import Any, Dict


def create_tool_executor(tool_class, execute_command_func=None):
    """
    Factory function to create tool executor from tool class

    Args:
        tool_class: The tool class to instantiate
        execute_command_func: The execute_command function to use.
            If None, falls back to core.execution.execute_command at call time
            (lazy import to avoid circular imports during module loading).

    Returns:
        An executor function that takes (target, params) and returns execution results
    """

    def executor(target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        exec_func = execute_command_func
        if exec_func is None:
            from core.execution import execute_command

            exec_func = execute_command
        tool = tool_class()
        return tool.execute(target, params, exec_func)

    return executor
