import binascii
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

_HEX_RE = re.compile(r'^[0-9a-fA-F\s]+$')
_MIN_SCORE = 0.6


def run(params: dict) -> dict:
    text = params.get("input", "")
    key = params.get("key", "")
    if not key:
        raise ValueError("Key must not be empty")
    data = text.encode("utf-8", errors="surrogateescape")
    key_bytes = key.encode("utf-8", errors="surrogateescape")
    out = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return {"output": binascii.hexlify(out).decode("ascii")}


def _score(text: str) -> float:
    if not text:
        return 0.0
    if any(c == "�" or (not c.isprintable() and c not in " \t\n\r") for c in text):
        return 0.0
    letters = sum(1 for c in text if c.isalpha())
    if letters == 0 or len(set(text)) < 4:
        return 0.0
    letters_and_space = letters + sum(1 for c in text if c == " ")
    return letters_and_space / len(text)


def _decloak_try(text: str) -> "str | None":
    stripped = "".join(text.split())
    if len(stripped) < 32 or len(stripped) % 2 != 0 or not _HEX_RE.match(stripped):
        return None
    try:
        raw = bytes.fromhex(stripped)
    except ValueError:
        return None

    best = None
    best_score = -1.0
    for key_byte in range(1, 256):
        candidate_bytes = bytes(b ^ key_byte for b in raw)
        try:
            candidate = candidate_bytes.decode("utf-8")
        except UnicodeDecodeError:
            continue
        s = _score(candidate)
        if s > best_score:
            best_score = s
            best = candidate

    if best is None or best_score < _MIN_SCORE:
        return None
    return best


OPERATION = Operation(
    id="xor_cipher",
    category="ciphers",
    name="XOR Cipher",
    description="XOR text against a repeating key, output as hex.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="key", label="Key", type="text", required=True),
    ],
    decloak_try=_decloak_try,
    decloak_priority=18,
)
