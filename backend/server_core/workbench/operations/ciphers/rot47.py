from backend.server_core.workbench.registry import Operation, ParamSpec


def _rot47_char(c: str) -> str:
    code = ord(c)
    if 33 <= code <= 126:
        return chr(33 + ((code - 33 + 47) % 94))
    return c


def run(params: dict) -> dict:
    text = params.get("input", "")
    return {"output": "".join(_rot47_char(c) for c in text)}


def _decloak_try(text: str) -> "str | None":
    if not text.strip():
        return None
    return "".join(_rot47_char(c) for c in text)


OPERATION = Operation(
    id="rot47",
    category="ciphers",
    name="ROT47",
    description="Apply the ROT47 letter-substitution cipher over printable ASCII (self-inverse).",
    run=run,
    params=[ParamSpec(name="input", label="Input", type="textarea", required=True)],
    decloak_try=_decloak_try,
    decloak_priority=901,
)
