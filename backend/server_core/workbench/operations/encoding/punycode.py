from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["decode", "encode"]


def run(params: dict) -> dict:
    text = params.get("input", "").strip()
    mode = params.get("mode", "decode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")
    if not text:
        raise ValueError("Input must not be empty")

    try:
        if mode == "encode":
            output = text.encode("idna").decode("ascii")
        else:
            output = text.encode("ascii").decode("idna")
    except UnicodeError as e:
        raise ValueError(f"Invalid domain for punycode {mode}: {e}")

    return {"output": output}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if not stripped or " " in stripped:
        return None
    labels = stripped.split(".")
    if not any(label.lower().startswith("xn--") for label in labels):
        return None
    try:
        return run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None


OPERATION = Operation(
    id="punycode",
    category="encoding",
    name="Punycode / IDN",
    description="Decode an xn-- punycode hostname to Unicode, or encode a Unicode domain to punycode.",
    run=run,
    params=[
        ParamSpec(name="input", label="Domain", type="text", required=True, help_text="e.g. xn--mnchen-3ya.de"),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="decode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=8,
)
