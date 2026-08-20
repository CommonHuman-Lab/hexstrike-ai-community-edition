import base64
import binascii
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]+={0,2}$')
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
        encoded = base64.urlsafe_b64encode(text.encode("utf-8", errors="surrogateescape"))
        return {"output": encoded.decode("ascii")}

    stripped = text.strip()
    try:
        padded = stripped + "=" * (-len(stripped) % 4)
        translated = padded.translate(str.maketrans("-_", "+/"))
        decoded = base64.b64decode(translated, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ValueError(f"Invalid Base64url input: {e}")
    return {"output": decoded.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 8 or ("-" not in stripped and "_" not in stripped):
        return None
    if not _B64URL_RE.match(stripped):
        return None
    try:
        output = run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None
    if not output or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


OPERATION = Operation(
    id="base64url",
    category="encoding",
    name="Base64 (URL-safe)",
    description="Encode text as URL-safe Base64 (-_ alphabet), or decode it back to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=21,
)
