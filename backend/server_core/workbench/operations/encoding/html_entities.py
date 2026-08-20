import html
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_ENTITY_RE = re.compile(r'&(#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);')


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "encode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "decode":
        return {"output": html.unescape(text)}
    return {"output": html.escape(text, quote=True)}


def _decloak_try(text: str) -> "str | None":
    if not _ENTITY_RE.search(text):
        return None
    decoded = html.unescape(text)
    if decoded == text or "�" in decoded:
        return None
    return decoded


OPERATION = Operation(
    id="html_entities",
    category="encoding",
    name="HTML Entities",
    description="Escape HTML-significant characters as entities, or decode entities back to characters.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=15,
)
