import base64
import binascii
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_B85_RE = re.compile(r'^[!-uz]+$')
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
        data = text.encode("utf-8", errors="surrogateescape")
        return {"output": base64.a85encode(data).decode("ascii")}

    try:
        raw = base64.a85decode(text.strip().encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as e:
        raise ValueError(f"Invalid Base85/Ascii85 input: {e}")
    return {"output": raw.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 8 or " " in stripped or not _B85_RE.match(stripped):
        return None
    try:
        output = run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None
    if not output or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


OPERATION = Operation(
    id="base85",
    category="encoding",
    name="Base85 (Ascii85)",
    description="Base85/Ascii85 encode or decode text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=40,
)
