import base64
import binascii

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["decode", "encode"]


def run(params: dict) -> dict:
    text = params.get("input", "").strip()
    mode = params.get("mode", "decode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")
    if not text:
        raise ValueError("Input must not be empty")

    if mode == "encode":
        if ":" not in text:
            raise ValueError("Input must be in user:pass format")
        encoded = base64.b64encode(text.encode("utf-8")).decode("ascii")
        return {"output": f"Basic {encoded}"}

    token = text[6:].strip() if text.lower().startswith("basic ") else text
    try:
        padded = token + "=" * (-len(token) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid Base64 input: {e}")
    if ":" not in decoded:
        raise ValueError("Decoded value is not in user:pass format")
    return {"output": decoded}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if not stripped.lower().startswith("basic "):
        return None
    try:
        return run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None


OPERATION = Operation(
    id="basic_auth",
    category="analysis",
    name="Basic Auth",
    description="Decode an Authorization: Basic header to user:pass, or encode user:pass into one.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="decode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=14,
)
