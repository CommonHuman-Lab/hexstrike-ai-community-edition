import base64
import binascii
import gzip
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["compress", "decompress"]

_B64_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "compress")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "compress":
        compressed = gzip.compress(text.encode("utf-8", errors="surrogateescape"))
        return {"output": base64.b64encode(compressed).decode("ascii")}

    stripped = text.strip()
    try:
        raw = base64.b64decode(stripped, validate=True)
        decompressed = gzip.decompress(raw)
    except (binascii.Error, ValueError, OSError) as e:
        raise ValueError(f"Invalid gzip/Base64 input: {e}")
    return {"output": decompressed.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 8 or not _B64_RE.match(stripped):
        return None
    try:
        raw = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None
    if raw[:2] != b'\x1f\x8b':
        return None
    try:
        return gzip.decompress(raw).decode("utf-8", errors="replace")
    except OSError:
        return None


OPERATION = Operation(
    id="gzip",
    category="compression",
    name="Gzip",
    description="Gzip-compress text to Base64, or decompress Base64-encoded Gzip data.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="compress"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=12,
)
