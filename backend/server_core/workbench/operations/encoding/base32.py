import base64
import binascii
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_B32_RE = re.compile(r'^[A-Z2-7]+=*$')
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
        encoded = base64.b32encode(text.encode("utf-8", errors="surrogateescape"))
        return {"output": encoded.decode("ascii")}

    stripped = text.strip().upper()
    padded = stripped + "=" * (-len(stripped) % 8)
    try:
        decoded = base64.b32decode(padded)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid Base32 input: {e}")
    return {"output": decoded.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip().upper()
    if len(stripped) < 8 or not _B32_RE.match(stripped):
        return None
    try:
        output = run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None
    if not output or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


OPERATION = Operation(
    id="base32",
    category="encoding",
    name="Base32",
    description="Encode text as Base32, or decode Base32 back to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=25,
)
