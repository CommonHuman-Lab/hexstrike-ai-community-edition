from backend.server_core.workbench.registry import Operation, ParamSpec

PREFIX_ALGORITHMS = [
    ("$2a$", "bcrypt"),
    ("$2b$", "bcrypt"),
    ("$2y$", "bcrypt"),
    ("$1$", "MD5 crypt"),
    ("$5$", "SHA-256 crypt"),
    ("$6$", "SHA-512 crypt"),
    ("$P$", "phpass (phpBB/WordPress)"),
    ("$H$", "phpass (phpBB/WordPress)"),
    ("pbkdf2_sha256$", "Django PBKDF2-SHA256"),
    ("pbkdf2_sha1$", "Django PBKDF2-SHA1"),
]

HEX_LENGTH_ALGORITHMS = {
    32: ["MD5", "NTLM", "MD4"],
    40: ["SHA-1", "RIPEMD-160"],
    56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512"],
}


def run(params: dict) -> dict:
    text = params.get("input", "").strip()
    if not text:
        raise ValueError("Input must not be empty")

    candidates = [name for prefix, name in PREFIX_ALGORITHMS if text.startswith(prefix)]

    if not candidates and all(c in "0123456789abcdefABCDEF" for c in text):
        candidates = HEX_LENGTH_ALGORITHMS.get(len(text), [])

    note = f"Length: {len(text)} characters."
    if not candidates:
        return {"output": "No known hash format matched.", "note": note}
    return {"output": "\n".join(candidates), "note": note}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if not stripped:
        return None
    candidates = [name for prefix, name in PREFIX_ALGORITHMS if stripped.startswith(prefix)]
    if not candidates and all(c in "0123456789abcdefABCDEF" for c in stripped):
        candidates = HEX_LENGTH_ALGORITHMS.get(len(stripped), [])
    if not candidates:
        return None
    return "\n".join(candidates)


OPERATION = Operation(
    id="hash_identify",
    category="analysis",
    name="Hash Identifier",
    description="Guess likely hash algorithm(s) for a hash string based on its length, charset, and prefix.",
    run=run,
    params=[
        ParamSpec(name="input", label="Hash", type="textarea", required=True),
    ],
    decloak_try=_decloak_try,
    decloak_priority=5,
    decloak_terminal=True,
)
