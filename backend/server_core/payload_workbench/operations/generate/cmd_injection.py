from backend.server_core.payload_workbench.operations.generate._common import make_generate_operation

OPERATION = make_generate_operation(
    attack_type="cmd_injection",
    name="CI",
    description="OS command injection payloads.",
    complexity_choices=["basic", "advanced"],
)
