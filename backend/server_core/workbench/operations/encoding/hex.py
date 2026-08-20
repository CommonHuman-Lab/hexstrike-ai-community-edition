import binascii
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_HEX_RE = re.compile(r'^[0-9a-fA-F\s]+$')
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
        return {"output": text.encode("utf-8", errors="surrogateescape").hex()}

    stripped = "".join(text.split())
    try:
        decoded = binascii.unhexlify(stripped)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid hex input: {e}")
    return {"output": decoded.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = "".join(text.split())
    if len(stripped) < 8 or len(stripped) % 2 != 0 or not _HEX_RE.match(stripped):
        return None
    try:
        output = run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None
    if not output or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


OPERATION = Operation(
    id="hex",
    category="encoding",
    name="Hex",
    description="Encode text as hexadecimal, or decode hex back to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=10,
)
