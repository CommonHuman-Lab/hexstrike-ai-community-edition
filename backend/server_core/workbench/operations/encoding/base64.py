import base64
import binascii
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
_MIN_PRINTABLE_RATIO = 0.9


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c != "�" and (c.isprintable() or c in " \t\n\r"))
    return good / len(text)


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "encode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "encode":
        encoded = base64.b64encode(text.encode("utf-8", errors="surrogateescape"))
        return {"output": encoded.decode("ascii")}

    stripped = text.strip()
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid Base64 input: {e}")
    return {"output": decoded.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 8 or not _B64_RE.match(stripped):
        return None
    try:
        output = run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None
    if not output or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


OPERATION = Operation(
    id="base64",
    category="encoding",
    name="Base64",
    description="Encode text as Base64, or decode Base64 back to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=20,
)
