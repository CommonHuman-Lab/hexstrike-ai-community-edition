from commonhuman_payloads.encoders import XSS_EVASIONS

from backend.server_core.payload_workbench.operations.generate._common import make_generate_operation

OPERATION = make_generate_operation(
    attack_type="xss",
    name="XSS",
    description="Cross-site scripting payloads sourced from commonhuman-payloads (html/script/advanced contexts).",
    complexity_choices=["basic", "advanced", "bypass"],
    evasion_choices=XSS_EVASIONS,
)
