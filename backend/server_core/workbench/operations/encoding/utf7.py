import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_UTF7_SHIFT_RE = re.compile(r'\+[A-Za-z0-9+/]+')
_MIN_PRINTABLE_RATIO = 0.9


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c != "�" and (c.isprintable() or c in " \t\n\r"))
    return good / len(text)


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "encode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "encode":
        encoded = text.encode("utf-7")
        return {"output": encoded.decode("ascii")}

    try:
        decoded = text.encode("ascii").decode("utf-7")
    except (UnicodeDecodeError, UnicodeEncodeError) as e:
        raise ValueError(f"Invalid UTF-7 input: {e}")
    return {"output": decoded}


def _decloak_try(text: str) -> "str | None":
    if not _UTF7_SHIFT_RE.search(text):
        return None
    try:
        output = run({"input": text, "mode": "decode"})["output"]
    except ValueError:
        return None
    if not output or output == text or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


OPERATION = Operation(
    id="utf7",
    category="encoding",
    name="UTF-7",
    description="Encode text as UTF-7, or decode UTF-7 back to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=19,
)
