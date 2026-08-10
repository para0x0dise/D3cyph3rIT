"""Field decryption and the per-format magic constants.

Every encrypted field in a compiled AutoIt script is XORed with a PRNG
keystream. Which PRNG and which seed depends on the subtype:

===========  ==========  ==================  ===================
Subtype      PRNG        Strings             AutoIt versions
===========  ==========  ==================  ===================
``EA05``     MT19937     ANSI, 1 byte/char   3.2.x
``EA06``     RanRot-B    UTF-16LE            3.26 and later
===========  ==========  ==================  ===================

The constants below are transcribed from ``DeCompilerConfig.bas`` (which keeps
each value in a comment next to its variable) and cross-checked against the
defaults baked into ``Frm_Options.frm``.
"""

from dataclasses import dataclass
from typing import Optional

from .errors import Au3Error
from .prng import MT19937, RanRotB


@dataclass(frozen=True)
class FormatKeys:
    """The XOR constants for one subtype."""

    name: str

    #: Seed for decrypting the 4-byte ``FILE`` resource tag.
    file_tag: int

    #: ``(length_key, data_key)`` for the ">>>AUTOIT SCRIPT<<<" marker string.
    src_file_inst: tuple

    #: ``(length_key, data_key)`` for the path the script was compiled from.
    compiled_path: tuple

    #: XORed over both the compressed and uncompressed size fields.
    size: int

    #: XORed over the stored Adler32 field.
    checksum: int

    #: Added to the passphrase-hash checksum to seed the body keystream.
    body: int

    #: True for EA06: RanRot-B, UTF-16LE strings, tokenised payload.
    is_new: bool


EA05 = FormatKeys(
    name="EA05",
    file_tag=0x16FA,
    src_file_inst=(0x29BC, 0xA25E),
    compiled_path=(0x29AC, 0xF25E),
    size=0x45AA,
    checksum=0xC3D2,
    body=0x22AF,
    is_new=False,
)

EA06 = FormatKeys(
    name="EA06",
    file_tag=0x18EE,
    src_file_inst=(0xADBC, 0xB33F),
    compiled_path=(0xF820, 0xF479),
    size=0x87BC,
    checksum=0xA685,
    body=0x2477,
    is_new=True,
)

_BY_NAME = {b"EA05": EA05, b"EA06": EA06}


def keys_for(subtype: bytes) -> FormatKeys:
    try:
        return _BY_NAME[subtype]
    except KeyError:
        pretty = subtype.decode("latin-1") if subtype else "<missing>"
        raise Au3Error(
            f"unsupported script subtype {pretty!r}; this port handles EA05 and EA06"
        ) from None


def decrypt(data: bytes, seed: int, is_new: bool) -> bytes:
    """XOR ``data`` with the keystream for ``seed``.

    ``is_new`` picks RanRot-B (EA06) over MT19937 (EA05). Encryption is the same
    operation, so this round-trips.
    """
    if not data:
        return b""
    gen = RanRotB(seed) if is_new else MT19937(seed)
    next_byte = gen.next_byte
    return bytes(byte ^ next_byte() for byte in data)


class FieldReader:
    """Sequential reader over the script region, with the encrypted-field types.

    Mirrors the ``FileStream`` helpers in ``Decompile.bas``: ``int8``/``int32``
    for plain little-endian integers, and ``GetEncryptStr``/``GetEncryptStrNew``
    for the length-prefixed encrypted strings.
    """

    def __init__(self, data: bytes, position: int = 0, keys: Optional[FormatKeys] = None):
        self._data = data
        self.position = position
        self.keys = keys

    def __len__(self) -> int:
        return len(self._data)

    @property
    def remaining(self) -> int:
        return len(self._data) - self.position

    @property
    def eof(self) -> bool:
        return self.position >= len(self._data)

    def seek(self, position: int) -> None:
        self.position = position

    def skip(self, count: int) -> None:
        self.position += count

    def read(self, count: int) -> bytes:
        if count < 0:
            raise Au3Error(f"refusing to read a negative length ({count})")
        chunk = self._data[self.position : self.position + count]
        self.position += count
        return chunk

    def read_exact(self, count: int, what: str) -> bytes:
        chunk = self.read(count)
        if len(chunk) != count:
            raise Au3Error(
                f"truncated while reading {what}: wanted {count} bytes, got {len(chunk)}"
            )
        return chunk

    def uint8(self) -> int:
        return self.read_exact(1, "uint8")[0]

    def uint32(self) -> int:
        return int.from_bytes(self.read_exact(4, "uint32"), "little")

    def encrypted_string(self, length_key: int, data_key: int) -> str:
        """A length-prefixed encrypted string.

        The length is a plain XOR against ``length_key``. The payload seed is
        ``data_key + length`` - note that is the *character* count, so for EA06
        the seed uses the character count while twice that many bytes are read.
        """
        if self.keys is None:
            raise Au3Error("FieldReader needs keys before reading encrypted strings")

        length = self.uint32() ^ length_key
        if length < 0 or length > self.remaining:
            raise Au3Error(
                f"implausible string length {length} at offset 0x{self.position - 4:X} "
                f"({self.remaining} bytes left) - decryption has probably desynchronised"
            )

        seed = data_key + length
        if self.keys.is_new:
            raw = decrypt(self.read_exact(length * 2, "utf-16 string"), seed, True)
            return raw.decode("utf-16-le", errors="replace")
        raw = decrypt(self.read_exact(length, "ansi string"), seed, False)
        return raw.decode("latin-1", errors="replace")
