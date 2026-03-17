import logging
import re
import sys
from shared.colored_formatter import ColoredFormatter

_ANSI_ESCAPE = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')


class _PlainFormatter(logging.Formatter):
    """Formatter that strips ANSI escape codes — safe for log files and grep."""

    def format(self, record):
        formatted = super().format(record)
        return _ANSI_ESCAPE.sub('', formatted)


def setup_logging(log_file: str = 'hexstrike.log') -> logging.Logger:
    """Setup enhanced logging: colored console output + ANSI-stripped file output."""
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    # Clear existing handlers to avoid duplicate entries on re-call
    for handler in root.handlers[:]:
        root.removeHandler(handler)

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        "[HexStrike AI] %(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    root.addHandler(console_handler)

    # File handler — plain text, no ANSI codes
    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(_PlainFormatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        root.addHandler(file_handler)
    except PermissionError:
        root.warning("Could not open log file %s — logging to console only.", log_file)

    return root
