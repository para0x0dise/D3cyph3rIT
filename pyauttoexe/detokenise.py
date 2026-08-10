"""Turn an EA06 token stream back into AutoIt source.

Ported from ``DeTokeniser.bas``. From AutoIt 3.26 onwards the compiler does not
embed source text; it embeds a token stream, so decrypting and decompressing an
EA06 script yields a ``.tok`` file rather than readable code.

Stream layout: a little-endian ``int32`` line count, then a flat run of tokens.
Each token starts with a one-byte command; ``0x7F`` terminates a line.

======================  ==================================================
Command                 Payload
======================  ==================================================
``0x00``                ``int32`` index into the AutoIt keyword table
``0x01``                ``int32`` index into the built-in function table
``0x05``                ``int32`` literal
``0x10``-``0x1F``       ``int64`` literal
``0x20``-``0x2F``       IEEE754 double literal
``0x30``-``0x3F``       length-prefixed UTF-16LE string, see below
``0x40``-``0x58``       operator, no payload
``0x7F``                end of line
======================  ==================================================

Strings carry their own light obfuscation: an ``int32`` character count, then
that many UTF-16LE code units XORed with the low and high bytes of the count
(``DT_DecodeString``). The ``0x3x`` low nibble then says what the string is -
keyword, macro, variable, user string and so on.
"""

import logging
import struct
from typing import List, Optional

from .errors import DetokeniseError

log = logging.getLogger(__name__)

TOKEN_INT32 = 0x05
TOKEN_END_OF_LINE = 0x7F

#: Emitted as a trailer so the output is recognisable, mirroring
#: ``DETOKENISE_MAKER`` in the original.
DETOKENISE_MARKER = "; DeTokenise by pyauttoexe"

#: More than this many lines means we are not looking at a token stream.
MAX_PLAUSIBLE_LINES = 0x3BFEFF

#: ``GetAu3KeyWords()`` in ``mod_AU3_parser.bas``. Index 0 is a placeholder, so
#: the table is used as-is with the on-stream index.
KEYWORDS = (
    "<Dummy>", "AND", "OR", "NOT",
    "IF", "THEN", "ELSE", "ELSEIF", "ENDIF",
    "WHILE", "WEND", "DO", "UNTIL", "FOR", "NEXT", "TO", "STEP", "IN",
    "EXITLOOP", "CONTINUELOOP",
    "SELECT", "CASE", "ENDSELECT", "SWITCH", "ENDSWITCH", "CONTINUECASE",
    "DIM", "REDIM", "LOCAL", "GLOBAL", "CONST", "STATIC",
    "FUNC", "ENDFUNC", "RETURN", "EXIT",
    "BYREF", "WITH", "ENDWITH",
    "TRUE", "FALSE", "DEFAULT",
    "NULL", "VOLATILE", "ENUM",
)

#: Operator tokens 0x40..0x58, in order.
OPERATORS = {
    0x40: ",", 0x41: "=", 0x42: ">", 0x43: "<", 0x44: "<>", 0x45: ">=",
    0x46: "<=", 0x47: "(", 0x48: ")", 0x49: "+", 0x4A: "-", 0x4B: "/",
    0x4C: "*", 0x4D: "&", 0x4E: "[", 0x4F: "]", 0x50: "==", 0x51: "^",
    0x52: "+=", 0x53: "-=", 0x54: "/=", 0x55: "*=", 0x56: "&=",
    0x57: "?", 0x58: ":",
}

#: Operators that suppress the space before the next token. Note this stops at
#: 0x56, so the ternary ``?`` and ``:`` are deliberately excluded - that is what
#: ``RangeCheck(cmd, &H56, &H40)`` in the original does.
_SPACING_OPERATORS = range(0x40, 0x57)

_BUILTIN_FUNCS: Optional[List[str]] = None


def _builtin_functions() -> List[str]:
    """The AutoIt built-in function names, indexed by token 0x01."""
    global _BUILTIN_FUNCS
    if _BUILTIN_FUNCS is None:
        try:
            from importlib.resources import files

            text = (files("pyauttoexe") / "data" / "au3_builtin_funcs.txt").read_text("utf-8")
        except (ImportError, FileNotFoundError, ModuleNotFoundError):
            import os

            path = os.path.join(os.path.dirname(__file__), "data", "au3_builtin_funcs.txt")
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
        _BUILTIN_FUNCS = [line.strip() for line in text.splitlines() if line.strip()]
    return _BUILTIN_FUNCS


def looks_like_token_stream(data: bytes) -> bool:
    """Cheap sniff for a token stream, mirroring the guards in ``DeToken``."""
    if len(data) < 8:
        return False
    lines = int.from_bytes(data[:4], "little")
    if (lines & 0xFFFF) == 0x5A4D or lines == 0xDFEFF:  # 'MZ' / a UTF BOM
        return False
    if lines == 0 or (lines & 0x7FFFFFF) > MAX_PLAUSIBLE_LINES:
        return False
    # The first token of a real stream is a command byte we know.
    return data[4] in _KNOWN_FIRST_TOKENS


_KNOWN_FIRST_TOKENS = frozenset(
    {0x00, 0x01, TOKEN_INT32, TOKEN_END_OF_LINE}
    | set(range(0x10, 0x30))
    | set(range(0x30, 0x40))
    | set(OPERATORS)
)


def _make_autoit_string(raw: str) -> str:
    """Re-quote a user string, picking a quote character that works.

    ``MakeAutoItString`` in the original: prefer double quotes, fall back to
    single quotes if the text contains a double quote, and double-up embedded
    quotes when it contains both.
    """
    if '"' in raw:
        if "'" in raw:
            return '"' + raw.replace('"', '""') + '"'
        return "'" + raw + "'"
    return '"' + raw + '"'


def _format_int64(value: int) -> str:
    """Positive values print as decimal; negatives print as hex.

    ``DeTokeniser.bas`` re-reads the two halves and prints them as hex for
    negatives. It uses VB's ``Hex()``, which does not zero-pad, so a value like
    ``0xFFFFFFFF00000000`` comes out as ``0xFFFFFFFF0``. We zero-pad instead,
    which is what AutoIt would actually accept back.
    """
    if value < 0:
        return "0x%016X" % (value & 0xFFFFFFFFFFFFFFFF)
    return str(value)


def _format_double(value: float) -> str:
    if value != value or value in (float("inf"), float("-inf")):
        return str(value)
    if value == int(value) and abs(value) < 1e16:
        return str(int(value))
    return repr(value)


class _TokenReader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    @property
    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def _take(self, count: int, what: str) -> bytes:
        chunk = self.data[self.pos : self.pos + count]
        if len(chunk) != count:
            raise DetokeniseError(
                f"token stream ended mid-{what} at offset 0x{self.pos:X}"
            )
        self.pos += count
        return chunk

    def uint8(self) -> int:
        return self._take(1, "byte")[0]

    def int32(self) -> int:
        return struct.unpack("<i", self._take(4, "int32"))[0]

    def uint32(self) -> int:
        return struct.unpack("<I", self._take(4, "uint32"))[0]

    def int64(self) -> int:
        return struct.unpack("<q", self._take(8, "int64"))[0]

    def double(self) -> float:
        return struct.unpack("<d", self._take(8, "double"))[0]

    def obfuscated_string(self) -> str:
        """``DT_DecodeString``: count-prefixed UTF-16LE, XORed with the count."""
        size = self.uint32()
        byte_count = size * 2
        if size < 0 or byte_count > len(self.data) - self.pos:
            raise DetokeniseError(
                f"string at offset 0x{self.pos - 4:X} claims {size} characters, "
                "which runs past the end of the stream"
            )
        raw = bytearray(self._take(byte_count, "string"))
        key_low = size & 0xFF
        key_high = (size >> 8) & 0xFF
        for i in range(0, len(raw), 2):
            raw[i] ^= key_low
            raw[i + 1] ^= key_high
        return bytes(raw).decode("utf-16-le", errors="replace")


def detokenise(data: bytes, *, strict: bool = False) -> str:
    """Convert a token stream to AutoIt source text.

    With ``strict`` an unknown token aborts; otherwise it is emitted as a
    ``<?token?>`` placeholder so the rest of the script still comes out, which
    is usually what you want when triaging a damaged or novel sample.
    """
    # The smallest legal stream is a line count plus a single end-of-line byte.
    if len(data) < 5:
        raise DetokeniseError(f"token stream is only {len(data)} bytes")

    reader = _TokenReader(data)
    line_count = reader.int32()
    if line_count <= 0 or (line_count & 0x7FFFFFF) > MAX_PLAUSIBLE_LINES:
        raise DetokeniseError(
            f"implausible line count {line_count}; this does not look like a token stream"
        )
    log.debug("token stream declares %d lines", line_count)

    keywords = KEYWORDS
    builtins = _builtin_functions()

    lines: List[str] = []
    parts: List[str] = []
    last_atom = ""

    # Spacing state, mirroring the original. `pending_space` is the delayed
    # flag from DelayedReturn(): a keyword forces a space after itself as well
    # as before. `after_operator` suppresses the leading space.
    pending_space = False
    after_operator = True

    while len(lines) < line_count and not reader.eof:
        cmd = reader.uint8()

        if cmd == TOKEN_END_OF_LINE:
            lines.append(" ".join(parts))
            parts = []
            after_operator = True
            pending_space = False
            last_atom = ""
            continue

        wants_space = False

        if cmd == TOKEN_INT32:
            value = reader.int32()
            atom = str(value)
            # AutoIt 3.3.8.1's tokeniser emits '+' followed by a negative
            # literal where the source said '-'. Drop the redundant '+' so the
            # output reads the way it was written.
            if value < 0 and last_atom == "+" and parts and parts[-1].endswith("+"):
                parts[-1] = parts[-1][:-1]
        elif 0x10 <= cmd <= 0x1F:
            atom = _format_int64(reader.int64())
        elif 0x20 <= cmd <= 0x2F:
            atom = _format_double(reader.double())
        elif cmd == 0x00:
            index = reader.int32()
            atom = keywords[index] if 0 <= index < len(keywords) else f"<?keyword {index}?>"
            wants_space = True
        elif cmd == 0x01:
            index = reader.int32()
            atom = builtins[index] if 0 <= index < len(builtins) else f"<?function {index}?>"
        elif 0x30 <= cmd <= 0x3F:
            text = reader.obfuscated_string()
            if cmd == 0x30:  # keyword
                atom = text
                wants_space = True
            elif cmd == 0x31:  # built-in function call
                atom = text
            elif cmd == 0x32:  # macro
                atom = "@" + text
            elif cmd == 0x33:  # variable
                atom = text if text.startswith("$") else "$" + text
            elif cmd == 0x34:  # user-defined function
                atom = text
            elif cmd == 0x35:  # object property
                atom = "." + text
            elif cmd == 0x36:  # string literal
                atom = _make_autoit_string(text)
            elif cmd == 0x37:  # preprocessor directive
                atom = text
                wants_space = True
            else:
                if strict:
                    raise DetokeniseError(
                        f"unknown string token 0x{cmd:02X} at offset 0x{reader.pos:X}"
                    )
                log.warning("unknown string token 0x%02X at offset 0x%X", cmd, reader.pos)
                atom = f"<?string token {cmd:#04x}: {text}?>"
        elif cmd in OPERATORS:
            atom = OPERATORS[cmd]
        else:
            if strict:
                raise DetokeniseError(
                    f"unknown token 0x{cmd:02X} at offset 0x{reader.pos - 1:X} "
                    f"on line {len(lines) + 1}"
                )
            log.warning(
                "unknown token 0x%02X at offset 0x%X (line %d)", cmd, reader.pos - 1, len(lines) + 1
            )
            atom = f"<?token {cmd:#04x}?>"

        if pending_space or (wants_space and not after_operator):
            parts.append(atom)
        elif parts:
            parts[-1] += atom
        else:
            parts.append(atom)

        pending_space = wants_space
        after_operator = cmd in _SPACING_OPERATORS
        last_atom = atom

    if parts:
        lines.append(" ".join(parts))

    if len(lines) < line_count:
        log.warning("token stream ended early: got %d of %d lines", len(lines), line_count)

    lines.append(DETOKENISE_MARKER)
    return "\r\n".join(lines) + "\r\n"
