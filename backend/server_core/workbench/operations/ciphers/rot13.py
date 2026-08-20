import codecs

from backend.server_core.workbench.registry import Operation, ParamSpec


def run(params: dict) -> dict:
    text = params.get("input", "")
    return {"output": codecs.encode(text, "rot_13")}


def _decloak_try(text: str) -> "str | None":
    if not text.strip():
        return None
    return codecs.encode(text, "rot_13")


OPERATION = Operation(
    id="rot13",
    category="ciphers",
    name="ROT13",
    description="Apply the ROT13 letter-substitution cipher (self-inverse).",
    run=run,
    params=[ParamSpec(name="input", label="Input", type="textarea", required=True)],
    decloak_try=_decloak_try,
    decloak_priority=900,
)
