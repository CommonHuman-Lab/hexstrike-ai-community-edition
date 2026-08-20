import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["to_charcode", "from_charcode"]
BASES = ["decimal", "hexadecimal", "binary"]
RADIX = {"decimal": 10, "hexadecimal": 16, "binary": 2}

_BINARY_TOKEN_RE = re.compile(r'^[01]{8}$')
_DECIMAL_TOKEN_RE = re.compile(r'^\d{1,7}$')
_HEX_TOKEN_RE = re.compile(r'^[0-9a-fA-F]{1,6}$')
_MAX_CODEPOINT = 0x10FFFF
_MIN_PRINTABLE_RATIO = 0.9


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "to_charcode")
    base = params.get("base", "decimal")
    delimiter = params.get("delimiter", " ")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")
    if base not in BASES:
        raise ValueError(f"Unsupported base: {base}")

    if mode == "to_charcode":
        if base == "decimal":
            codes = [str(ord(c)) for c in text]
        elif base == "binary":
            codes = [format(ord(c), "08b") for c in text]
        else:
            codes = [format(ord(c), "x") for c in text]
        return {"output": delimiter.join(codes)}

    if not text.strip():
        raise ValueError("Input must not be empty")
    tokens = [t for t in (text.split(delimiter) if delimiter else text.split())]
    tokens = [t.strip() for t in tokens if t.strip()]
    try:
        chars = [chr(int(t, RADIX[base])) for t in tokens]
    except ValueError:
        raise ValueError(f"Invalid {base} code point in input")
    return {"output": "".join(chars)}


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for c in text if c != "�" and (c.isprintable() or c in " \t\n\r"))
    return good / len(text)


def _tokenize(text: str) -> "list[str]":
    tokens = text.split()
    if len(tokens) < 2:
        tokens = [t.strip() for t in text.split(",") if t.strip()]
    return tokens


def _try_base(tokens: "list[str]", base: str) -> "str | None":
    try:
        output = run({"input": " ".join(tokens), "mode": "from_charcode", "base": base, "delimiter": ""})["output"]
    except ValueError:
        return None
    if not output or _printable_ratio(output) < _MIN_PRINTABLE_RATIO:
        return None
    return output


def _decloak_try(text: str) -> "str | None":
    tokens = _tokenize(text.strip())
    if len(tokens) < 2:
        return None
    if all(_BINARY_TOKEN_RE.match(t) for t in tokens):
        result = _try_base(tokens, "binary")
        if result is not None:
            return result
    if all(_DECIMAL_TOKEN_RE.match(t) and int(t) <= _MAX_CODEPOINT for t in tokens):
        result = _try_base(tokens, "decimal")
        if result is not None:
            return result
    if all(_HEX_TOKEN_RE.match(t) and int(t, 16) <= _MAX_CODEPOINT for t in tokens):
        result = _try_base(tokens, "hexadecimal")
        if result is not None:
            return result
    return None


OPERATION = Operation(
    id="charcode_convert",
    category="encoding",
    name="Charcode Convert",
    description="Convert text to a list of Unicode code points, or back from code points to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="to_charcode"),
        ParamSpec(name="base", label="Base", type="select", choices=BASES, default="decimal"),
        ParamSpec(name="delimiter", label="Delimiter", type="text", default=" "),
    ],
    decloak_try=_decloak_try,
    decloak_priority=17,
)
