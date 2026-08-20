import re

from backend.server_core.workbench.registry import Operation, ParamSpec

MODES = ["encode", "decode"]

MORSE_TABLE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..",
    "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-",
    "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----.",
    ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--",
    "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...",
    ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-", "_": "..--.-",
    '"': ".-..-.", "$": "...-..-", "@": ".--.-.",
}
REVERSE_MORSE_TABLE = {v: k for k, v in MORSE_TABLE.items()}

_MORSE_CHARSET_RE = re.compile(r'^[.\-/ ]+$')


def run(params: dict) -> dict:
    text = params.get("input", "")
    mode = params.get("mode", "encode")
    if mode not in MODES:
        raise ValueError(f"Unsupported mode: {mode}")

    if mode == "encode":
        words = text.upper().split()
        if not words:
            raise ValueError("Input must not be empty")
        encoded_words = []
        for word in words:
            letters = []
            for ch in word:
                if ch not in MORSE_TABLE:
                    raise ValueError(f"No Morse mapping for character: {ch!r}")
                letters.append(MORSE_TABLE[ch])
            encoded_words.append(" ".join(letters))
        return {"output": " / ".join(encoded_words)}

    stripped = text.strip()
    if not stripped:
        raise ValueError("Input must not be empty")
    words = stripped.split("/")
    decoded_words = []
    for word in words:
        chars = []
        for code in word.split():
            if code not in REVERSE_MORSE_TABLE:
                raise ValueError(f"Invalid Morse code token: {code!r}")
            chars.append(REVERSE_MORSE_TABLE[code])
        decoded_words.append("".join(chars))
    return {"output": " ".join(decoded_words)}


def _decloak_try(text: str) -> "str | None":
    stripped = text.strip()
    if len(stripped) < 3 or not _MORSE_CHARSET_RE.match(stripped) or not any(c in ".-" for c in stripped):
        return None
    try:
        return run({"input": stripped, "mode": "decode"})["output"]
    except ValueError:
        return None


OPERATION = Operation(
    id="morse_code",
    category="encoding",
    name="Morse Code",
    description="Encode text as International Morse code, or decode Morse code back to text.",
    run=run,
    params=[
        ParamSpec(name="input", label="Input", type="textarea", required=True),
        ParamSpec(name="mode", label="Mode", type="select", choices=MODES, default="encode"),
    ],
    decloak_try=_decloak_try,
    decloak_priority=9,
)
