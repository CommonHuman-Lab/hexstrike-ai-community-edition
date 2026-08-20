import logging
import re

# ANSI color codes (inlined to avoid importing from mcp_client)
_COLORS = {
    'DEBUG':    '\033[38;5;240m',  # gray
    'INFO':     '\033[38;5;46m',   # bright green
    'WARNING':  '\033[38;5;208m',  # orange
    'ERROR':    '\033[38;5;196m',  # bright red
    'CRITICAL': '\033[48;5;196m\033[38;5;15m\033[1m',  # red bg, white bold
}
_BRIGHT_WHITE = '\033[97m'
_RESET = '\033[0m'

# Almost everything logs at INFO, so leaving it all bright green makes the
# console unreadable at a glance. Recolor by content so HTTP noise, cache
# events, and process lifecycle lines are visually distinct from each other
# and from genuine success/summary lines (which keep the default green).
_INFO_CATEGORY_COLORS = (
    (re.compile(r'"[A-Z]+ \S+ HTTP/1\.\d" \d{3}'), '\033[38;5;240m'),  # HTTP access logs — dim gray
    (re.compile(r'Cache (HIT|MISS)'), '\033[38;5;129m'),               # cache events — purple
    (re.compile(r'EXECUTING:|PROCESS:|PID |Task submitted to pool|Process pool worker'), '\033[38;5;51m'),  # process/task lifecycle — cyan
    (re.compile(r'TIMEOUT:'), '\033[38;5;208m'),                       # timeouts — orange
)

class ColoredFormatter(logging.Formatter):
    """Enhanced formatter with colors and emojis - matches server styling"""
    COLORS = _COLORS

    EMOJIS = {
        'DEBUG': '🔍',
        'INFO': '',
        'WARNING': '⚠️',
        'ERROR': '❌',
        'CRITICAL': '🔥'
    }

    _stream: object = None

    def format(self, record):
        record = logging.makeLogRecord(record.__dict__)
        emoji = self.EMOJIS.get(record.levelname, '📝')
        color = self.COLORS.get(record.levelname, _BRIGHT_WHITE)

        if record.levelname == 'INFO':
            msg_text = str(record.msg)
            for pattern, cat_color in _INFO_CATEGORY_COLORS:
                if pattern.search(msg_text):
                    color = cat_color
                    break

        # Only apply ANSI codes if the handler stream is a real TTY
        stream = getattr(self, '_stream', None)
        use_color = stream.isatty() if stream and hasattr(stream, 'isatty') else False

        if emoji is not None and emoji != '':
            record.msg = f"{color}{emoji} {record.msg}{_RESET}" if use_color else f"{emoji} {record.msg}"
        else:
            record.msg = f"{color}{record.msg}{_RESET}" if use_color else record.msg
        return super().format(record)