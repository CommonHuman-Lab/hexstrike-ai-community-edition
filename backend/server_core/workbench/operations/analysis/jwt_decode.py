import binascii
import json
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

from ._jwt_common import decode_segment

_JWT_SEGMENT_RE = re.compile(r'^[A-Za-z0-9_-]+$')


def run(params: dict) -> dict:
    token = params.get("input", "").strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (expected header.payload.signature)")
    try:
        header = decode_segment(parts[0])
        payload = decode_segment(parts[1])
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid JWT segment: {e}")
    result = {"header": header, "payload": payload}
    return {
        "output": json.dumps(result, indent=2),
        "note": "Signature not verified — this only decodes header and payload.",
    }


def _decloak_try(text: str) -> "str | None":
    token = text.strip()
    parts = token.split(".")
    if len(parts) != 3 or not all(p and _JWT_SEGMENT_RE.match(p) for p in parts):
        return None
    try:
        header = decode_segment(parts[0])
        payload = decode_segment(parts[1])
    except (binascii.Error, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return json.dumps({"header": header, "payload": payload}, indent=2)


OPERATION = Operation(
    id="jwt_decode",
    category="analysis",
    name="JWT Decode",
    description="Decode a JWT's header and payload. Does not verify the signature.",
    run=run,
    params=[ParamSpec(name="input", label="Token", type="textarea", required=True)],
    decloak_try=_decloak_try,
    decloak_priority=6,
    decloak_terminal=True,
)
