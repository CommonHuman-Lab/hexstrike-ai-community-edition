from backend.server_core.workbench.registry import Operation, ParamSpec


def _atbash_char(c: str) -> str:
    if "a" <= c <= "z":
        return chr(ord("z") - (ord(c) - ord("a")))
    if "A" <= c <= "Z":
        return chr(ord("Z") - (ord(c) - ord("A")))
    return c


def run(params: dict) -> dict:
    text = params.get("input", "")
    return {"output": "".join(_atbash_char(c) for c in text)}


def _decloak_try(text: str) -> "str | None":
    if not text.strip():
        return None
    return "".join(_atbash_char(c) for c in text)


OPERATION = Operation(
    id="atbash",
    category="ciphers",
    name="Atbash",
    description="Apply the Atbash substitution cipher (A<->Z, B<->Y, ...), case-preserving (self-inverse).",
    run=run,
    params=[ParamSpec(name="input", label="Input", type="textarea", required=True)],
    decloak_try=_decloak_try,
    decloak_priority=902,
)
