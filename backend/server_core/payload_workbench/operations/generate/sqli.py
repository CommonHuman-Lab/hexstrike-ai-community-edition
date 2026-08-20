from commonhuman_payloads.encoders import (
    EVASION_NONE,
    EVASION_SQL_BETWEEN,
    EVASION_SQL_BLANK_CHARS,
    EVASION_SQL_CASE,
    EVASION_SQL_COMMENT,
    EVASION_SQL_ENCODE,
    EVASION_SQL_EQUALTOLIKE,
    EVASION_SQL_MULTILINE,
    EVASION_SQL_RANDOM_COMMENTS,
    EVASION_SQL_SPACE_DASH,
    EVASION_SQL_SPACE_HASH,
    EVASION_SQL_SPACE_PLUS,
    EVASION_SQL_VERSIONED,
    EVASION_SQL_WHITESPACE,
)

from backend.server_core.payload_workbench.operations.generate._common import make_generate_operation

SQL_EVASIONS = [
    EVASION_NONE,
    EVASION_SQL_COMMENT,
    EVASION_SQL_WHITESPACE,
    EVASION_SQL_CASE,
    EVASION_SQL_ENCODE,
    EVASION_SQL_MULTILINE,
    EVASION_SQL_VERSIONED,
    EVASION_SQL_SPACE_DASH,
    EVASION_SQL_SPACE_HASH,
    EVASION_SQL_SPACE_PLUS,
    EVASION_SQL_BLANK_CHARS,
    EVASION_SQL_RANDOM_COMMENTS,
    EVASION_SQL_EQUALTOLIKE,
    EVASION_SQL_BETWEEN,
]

OPERATION = make_generate_operation(
    attack_type="sqli",
    name="SQLi",
    description="SQL injection payloads sourced from commonhuman-payloads (boolean/error/UNION/time-based).",
    complexity_choices=["basic", "advanced", "time_based"],
    evasion_choices=SQL_EVASIONS,
)
