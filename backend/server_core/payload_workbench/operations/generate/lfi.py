from backend.server_core.payload_workbench.operations.generate._common import make_generate_operation

OPERATION = make_generate_operation(
    attack_type="lfi",
    name="LFI",
    description="Local file inclusion / directory traversal payloads.",
    complexity_choices=["basic", "advanced"],
)
