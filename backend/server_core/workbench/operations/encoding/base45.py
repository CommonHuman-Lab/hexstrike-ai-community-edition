import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_B45_RE = re.compile(r'^[0-9A-Z $%*+\-./:]+$')
_MIN_PRINTABLE_RATIO = 0.9


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c != "�" and (c.isprintable() or c in " \t\n\r"))
    return good / len(text)


def _b45encode(data: bytes) -> str:
    out = []
    for i in range(0, len(data) - 1, 2):
        n = data[i] * 256 + data[i + 1]
        c = n % 45
        n //= 45
        d = n % 45
        e = n // 45
        out.append(ALPHABET[c] + ALPHABET[d] + ALPHABET[e])
    if len(data) % 2 == 1:
        n = data[-1]
        c = n % 45
        d = n // 45
        out.append(ALPHABET[c] + ALPHABET[d])
    return "".join(out)


def _b45decode(text: str) -> bytes:
    index = {ch: i for i, ch in enumerate(ALPHABET)}
    out = bytearray()
    i = 0
    while i < len(text):
        chunk = text[i:i + 3]
        try:
            values = [index[ch] for ch in chunk]
        except KeyError as e:
            raise ValueError(f"Invalid Base45 character: {e}")
        if len(chunk) == 3:
            n = values[0] + values[1] * 45 + values[2] * 45 * 45
            if n > 0xFFFF:
                raise ValueError("Base45 value out of range")
            out += n.to_bytes(2, "big")
            i += 3
        elif len(chunk) == 2:
            n = values[0] + values[1] * 45
            if n > 0xFF:
                raise ValueError("Base45 value out of range")
            out.append(n)
            i += 2
        else:
            raise ValueError("Invalid Base45 length")
    return bytes(out)


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "encode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "encode":
        return {"output": _b45encode(text.encode("utf-8", errors="surrogateescape"))}

    stripped = text.strip()
    try:
        raw = _b45decode(stripped)
    except ValueError as e:
        raise ValueError(f"Invalid Base45 input: {e}")
    return {"output": raw.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 6 or len(stripped) % 3 == 1 or not _B45_RE.match(stripped):
        return None
    try:
        output = run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None
    if not output or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


OPERATION = Operation(
    id="base45",
    category="encoding",
    name="Base45",
    description="Encode text as Base45 (RFC 9285, used in QR codes / health certificates), or decode it back.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=42,
)
