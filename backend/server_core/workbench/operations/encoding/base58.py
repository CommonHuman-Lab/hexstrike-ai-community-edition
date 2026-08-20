import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_RE = re.compile(r'^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$')
_MIN_PRINTABLE_RATIO = 0.9


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c != "�" and (c.isprintable() or c in " \t\n\r"))
    return good / len(text)


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    digits = ""
    while n > 0:
        n, rem = divmod(n, 58)
        digits = ALPHABET[rem] + digits
    n_leading_zeros = len(data) - len(data.lstrip(b"\x00"))
    return "1" * n_leading_zeros + digits


def _b58decode(text: str) -> bytes:
    n = 0
    for ch in text:
        idx = ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"Invalid Base58 character: {ch!r}")
        n = n * 58 + idx
    n_leading_ones = len(text) - len(text.lstrip("1"))
    body_len = (n.bit_length() + 7) // 8
    body = n.to_bytes(body_len, "big") if n > 0 else b""
    return b"\x00" * n_leading_ones + body


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "encode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "encode":
        return {"output": _b58encode(text.encode("utf-8", errors="surrogateescape"))}

    stripped = text.strip()
    try:
        raw = _b58decode(stripped)
    except ValueError as e:
        raise ValueError(f"Invalid Base58 input: {e}")
    return {"output": raw.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 10 or not _B58_RE.match(stripped):
        return None
    try:
        output = run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None
    if not output or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


OPERATION = Operation(
    id="base58",
    category="encoding",
    name="Base58",
    description="Encode text as Base58 (Bitcoin alphabet), or decode Base58 back to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=45,
)
