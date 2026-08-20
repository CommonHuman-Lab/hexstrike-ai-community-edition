import base64
import binascii
import re
import zlib

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["compress", "decompress"]

_B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "compress")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "compress":
        compressed = zlib.compress(text.encode("utf-8", errors="surrogateescape"))
        return {"output": base64.b64encode(compressed).decode("ascii")}

    stripped = text.strip()
    try:
        raw = base64.b64decode(stripped, validate=True)
        decompressed = zlib.decompress(raw)
    except (binascii.Error, ValueError, zlib.error) as e:
        raise ValueError(f"Invalid zlib/Base64 input: {e}")
    return {"output": decompressed.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 8 or not _B64_RE.match(stripped):
        return None
    try:
        raw = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(raw) < 2 or (raw[0] & 0x0F) != 8 or ((raw[0] << 8) | raw[1]) % 31 != 0:
        return None
    try:
        return zlib.decompress(raw).decode("utf-8", errors="replace")
    except zlib.error:
        return None


OPERATION = Operation(
    id="zlib",
    category="compression",
    name="Zlib",
    description="Zlib-compress text to Base64, or decompress Base64-encoded Zlib data.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="compress"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=13,
)
