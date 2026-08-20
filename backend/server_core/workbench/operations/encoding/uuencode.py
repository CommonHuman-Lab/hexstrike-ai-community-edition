import binascii
import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

_BEGIN_RE = re.compile(r'(^|\n)begin [0-7]{3} \S+')


def _uu_encode(data: bytes, filename: str, mode: str) -> str:
    lines = [f"begin {mode} {filename}"]
    for i in range(0, len(data), 45):
        chunk = data[i:i + 45]
        lines.append(binascii.b2a_uu(chunk).decode("ascii").rstrip("\n"))
    lines.append("`")
    lines.append("end")
    return "\n".join(lines)


def _uu_decode(text: str) -> bytes:
    out = bytearray()
    in_body = False
    for line in text.splitlines():
        if line.startswith("begin "):
            in_body = True
            continue
        if line.strip() == "end":
            break
        if not in_body:
            continue
        if not line.strip() or line.strip() == "`":
            continue
        try:
            out += binascii.a2b_uu(line + "\n")
        except (binascii.Error, ValueError) as e:
            raise ValueError(f"Invalid uuencoded line: {e}")
    return bytes(out)


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "encode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "encode":
        filename = params.get("filename", "data.txt") or "data.txt"
        file_mode = params.get("file_mode", "644") or "644"
        return {"output": _uu_encode(text.encode("utf-8", errors="surrogateescape"), filename, file_mode)}

    stripped = text.strip("\n")
    if not _BEGIN_RE.search("\n" + stripped):
        raise ValueError("Input is not in uuencode format (missing 'begin MODE FILENAME' header)")
    raw = _uu_decode(stripped)
    return {"output": raw.decode("utf-8", errors="replace")}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip("\n")
    if not _BEGIN_RE.search("\n" + stripped):
        return None
    try:
        return run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None


OPERATION = Operation(
    id="uuencode",
    category="encoding",
    name="UUencode",
    description="UUencode text into the classic begin/end Unix format, or decode it back to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
        ParamSpec(name="filename", label="Filename", type="text", default="data.txt", help_text="Only applies when encoding."),
        ParamSpec(name="file_mode", label="File mode", type="text", default="644", help_text="Only applies when encoding."),
    ],
    decloak_try=_decloak_try,
    decloak_priority=11,
)
