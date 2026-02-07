"""
Colored Formatter
Custom logging formatter with colors and emojis
"""

import logging

from core.visual import ModernVisualEngine


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors and emojis"""

    COLORS = {
        "DEBUG": ModernVisualEngine.COLORS["DEBUG"],
        "INFO": ModernVisualEngine.COLORS["SUCCESS"],
        "WARNING": ModernVisualEngine.COLORS["WARNING"],
        "ERROR": ModernVisualEngine.COLORS["ERROR"],
        "CRITICAL": ModernVisualEngine.COLORS["CRITICAL"],
    }

    EMOJIS = {"DEBUG": "🔍", "INFO": "✅", "WARNING": "⚠️", "ERROR": "❌", "CRITICAL": "🔥"}

    def format(self, record):
        emoji = self.EMOJIS.get(record.levelname, "📝")
        color = self.COLORS.get(record.levelname, ModernVisualEngine.COLORS["BRIGHT_WHITE"])

        # Add color and emoji to the message
        record.msg = f"{color}{emoji} {record.msg}{ModernVisualEngine.COLORS['RESET']}"
        return super().format(record)
