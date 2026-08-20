from commonhuman_payloads.encoders import ALL_EVASIONS, EVASION_NONE, apply_evasion

from backend.server_core.payload_workbench.registry import Operation, ParamSpec


def run(params: dict) -> dict:
    payload = params.get("input", "")
    technique = params.get("technique", EVASION_NONE)
    if technique not in ALL_EVASIONS:
        raise ValueError(f"Unsupported technique: {technique}")

    return {"output": apply_evasion(payload, technique)}


OPERATION = Operation(
    id="apply_evasion",
    category="evasion",
    name="Apply WAF evasion",
    description="Apply a single WAF-evasion transform (case mixing, encoding, comment injection, ...) to a payload.",
    run=run,
    params=[
        ParamSpec(name="input", label="Payload", type="textarea", required=True),
        ParamSpec(name="technique", label="Technique", type="select",
                  choices=ALL_EVASIONS, default=EVASION_NONE),
    ],
)
