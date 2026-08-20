from commonhuman_payloads.encoders import EVASION_NONE, XSS_EVASIONS, apply_evasion
from commonhuman_payloads.waf import WAF_EXTRA_PAYLOADS, get_waf_payloads

from backend.server_core.payload_workbench.registry import Operation, ParamSpec

WAF_NAMES = sorted(WAF_EXTRA_PAYLOADS)
MARKER = "XSS"


def run(params: dict) -> dict:
    waf_name = params.get("waf_name", WAF_NAMES[0] if WAF_NAMES else "")
    if waf_name not in WAF_EXTRA_PAYLOADS:
        raise ValueError(f"Unsupported waf_name: {waf_name}")

    evasion = params.get("evasion", EVASION_NONE)
    if evasion not in XSS_EVASIONS:
        raise ValueError(f"Unsupported evasion technique: {evasion}")

    payloads = [p.replace("{marker}", MARKER) for p in get_waf_payloads(waf_name)]
    if evasion != EVASION_NONE:
        payloads = [apply_evasion(p, evasion) for p in payloads]
    return {"output": "\n".join(payloads)}


OPERATION = Operation(
    id="generate_waf_bypass",
    category="generate",
    name="WAF bypass",
    description="Vendor-specific WAF bypass payloads from commonhuman-payloads.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", hidden=True),
        ParamSpec(name="waf_name", label="WAF vendor", type="select",
                  choices=WAF_NAMES, default=(WAF_NAMES[0] if WAF_NAMES else "")),
        ParamSpec(name="evasion", label="WAF evasion", type="select",
                  choices=XSS_EVASIONS, default=EVASION_NONE,
                  help_text="Apply an additional WAF-evasion transform to each payload"),
    ],
)
