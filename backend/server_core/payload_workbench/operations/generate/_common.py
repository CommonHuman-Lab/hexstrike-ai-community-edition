from typing import List, Optional

from commonhuman_payloads.encoders import EVASION_NONE, apply_evasion

from backend.server_core.generators.payload_generator import ai_payload_generator
from backend.server_core.payload_workbench.registry import Operation, ParamSpec


def make_generate_operation(
    attack_type: str,
    name: str,
    description: str,
    complexity_choices: list,
    evasion_choices: Optional[List[str]] = None,
) -> Operation:
    def run(params: dict) -> dict:
        complexity = params.get("complexity", complexity_choices[0])
        if complexity not in complexity_choices:
            raise ValueError(f"Unsupported complexity for {attack_type}: {complexity}")

        result = ai_payload_generator.generate_contextual_payload({
            "attack_type": attack_type,
            "complexity": complexity,
            "technology": params.get("technology", ""),
        })
        payloads = [p["payload"] for p in result["payloads"] if p["encoding"] == "none"]

        if evasion_choices:
            evasion = params.get("evasion", EVASION_NONE)
            if evasion not in evasion_choices:
                raise ValueError(f"Unsupported evasion technique: {evasion}")
            if evasion != EVASION_NONE:
                payloads = [apply_evasion(p, evasion) for p in payloads]

        return {"output": "\n".join(payloads)}

    params = [
        ParamSpec(name="input", label="Input", type="textarea", hidden=True),
        ParamSpec(name="complexity", label="Complexity", type="select",
                  choices=complexity_choices, default=complexity_choices[0]),
        ParamSpec(name="technology", label="Target technology", type="text", required=False,
                  help_text="e.g. php, nodejs, jsp (optional)"),
    ]
    if evasion_choices:
        params.append(ParamSpec(name="evasion", label="WAF evasion", type="select",
                                 choices=evasion_choices, default=EVASION_NONE,
                                 help_text="Apply a WAF-evasion transform to each generated payload"))

    return Operation(
        id=f"generate_{attack_type}",
        category="generate",
        name=name,
        description=description,
        run=run,
        params=params,
    )
