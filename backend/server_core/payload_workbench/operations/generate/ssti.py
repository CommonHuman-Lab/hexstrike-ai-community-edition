from backend.server_core.payload_workbench.operations.generate._common import make_generate_operation

OPERATION = make_generate_operation(
    attack_type="ssti",
    name="SSTI",
    description="Server-side template injection payloads.",
    complexity_choices=["basic", "advanced"],
)
