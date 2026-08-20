import re
from urllib.parse import quote, unquote

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_PERCENT_ESCAPE_RE = re.compile(r'%[0-9a-fA-F]{2}')


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "encode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "decode":
        return {"output": unquote(text)}

    safe = "" if str(params.get("encode_all", "false")).lower() == "true" else "/"
    return {"output": quote(text, safe=safe)}


def _decloak_try(text: str) -> "str | None":
    if not _PERCENT_ESCAPE_RE.search(text):
        return None
    decoded = unquote(text)
    if decoded == text or "�" in decoded:
        return None
    return decoded


OPERATION = Operation(
    id="url_encoding",
    category="encoding",
    name="URL Encoding",
    description="Percent-encode text for a URL, or decode percent-encoded text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
        ParamSpec(
            name="encode_all",
            label="Encode slashes too",
            type="select",
            choices=["false", "true"],
            default="false",
            help_text="Only applies when encoding.",
        ),
    ],
    decloak_try=_decloak_try,
    decloak_priority=15,
)
