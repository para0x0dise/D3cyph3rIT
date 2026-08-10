"""The LZSS variant AutoIt uses for compressed script bodies.

Ported from ``JB01_Decompress.cpp`` (``!SourceCode/SRC LZSS/V1_02/``), which is
the source behind the ``data/LZSS.exe`` helper myAutToExe shells out to.

A compressed body opens with an 8-byte header: a 4-byte algorithm tag and the
uncompressed size as a **big-endian** u32. After that it is a bitstream of:

* a literal flag bit, followed by 8 bits - a literal byte
* the opposite flag bit, followed by 15 bits of backwards offset and a
  variable-length match length (see :func:`_read_match_len`) plus a minimum of 3

**EA05 and EA06 use opposite flag polarity.** EA05 spells a literal as ``0``
(``EA05_LITERAL`` in ``JB01_Decompress.h``); EA06 spells it as ``1``. Everything
else about the two streams is identical.

That difference is not in the checked-in V1_02 sources, which predate AutoIt
3.26 and only recognise ``JB01`` and ``EA05``. The bundled ``data/LZSS.exe`` is
a later build ("Extended Version 0.3 by CW2K") that does handle EA06. The
polarity was recovered by decoding the EA06 body of ``testSamples/R`` by hand
and confirmed by a byte-for-byte diff of this module's output against that
binary's, over all 4,427,632 bytes.

The ``JB01`` tag denotes an adaptive-Huffman variant used by AutoHotkey and
AutoIt2, which is out of scope for this port.
"""

import logging
from typing import Optional

from .errors import DecompressionError

log = logging.getLogger(__name__)

HEADER_SIZE = 8
MIN_MATCH_LEN = 3
WINDOW_BITS = 15

TAG_EA05 = b"EA05"
TAG_EA06 = b"EA06"
TAG_JB01 = b"JB01"

#: Which flag bit means "a literal byte follows", per tag. The two formats are
#: otherwise identical; see the module docstring.
LITERAL_BIT = {TAG_EA05: 0, TAG_EA06: 1}

#: Tags that use the plain (non-Huffman) bitstream this module implements.
SUPPORTED_TAGS = tuple(LITERAL_BIT)


class _BitReader:
    """MSB-first bit reader, refilling 16 bits at a time.

    A direct transcription of ``CompressedStreamReadBits``. The accumulator is a
    32-bit value whose high word collects the bits shifted out of the low word;
    the caller masks the high word off at the start of each read. Refills take
    two bytes, high byte first.
    """

    __slots__ = ("_data", "_pos", "_acc", "_bits_left")

    def __init__(self, data: bytes, pos: int = 0):
        self._data = data
        self._pos = pos
        self._acc = 0
        self._bits_left = 0

    @property
    def position(self) -> int:
        return self._pos

    def read(self, count: int) -> int:
        acc = self._acc & 0x0000FFFF
        data = self._data
        size = len(data)

        for _ in range(count):
            if self._bits_left == 0:
                # Past the end the original reads whatever fgetc returns; we
                # feed zeroes so a slightly short stream degrades rather than
                # crashing, and let the size check downstream catch it.
                if self._pos + 1 < size:
                    acc |= (data[self._pos] << 8) | data[self._pos + 1]
                elif self._pos < size:
                    acc |= data[self._pos] << 8
                self._pos += 2
                self._bits_left = 16
            acc = (acc << 1) & 0xFFFFFFFF
            self._bits_left -= 1

        self._acc = acc
        return acc >> 16


def _read_match_len(bits: _BitReader) -> int:
    """The escalating match-length code from ``CompressedStreamReadMatchLen``.

    Two bits cover 0-2; ``11`` escapes to three more bits for 3-9; ``111``
    escapes to five more for 10-40; ``11111`` escapes to eight more for 41-295;
    and ``11111111`` keeps adding 255 per extra byte after that.
    """
    length = 0
    temp = bits.read(2)
    if temp == 3:
        length = 3
        temp = bits.read(3)
        if temp == 7:
            length = 10
            temp = bits.read(5)
            if temp == 31:
                length = 41
                temp = bits.read(8)
                if temp == 255:
                    length = 0x128
                    temp = bits.read(8)
                    while temp == 255:
                        length += 255
                        temp = bits.read(8)
    return length + temp


def peek_header(data: bytes):
    """Return ``(tag, uncompressed_size)`` without decompressing."""
    if len(data) < HEADER_SIZE:
        raise DecompressionError(
            f"compressed body is only {len(data)} bytes, too short for an LZSS header"
        )
    return data[:4], int.from_bytes(data[4:8], "big")


def decompress(data: bytes, expected_size: Optional[int] = None) -> bytes:
    """Inflate an EA05/EA06 LZSS body, header included.

    ``expected_size`` is the size the FILE record advertised; it is only used to
    cross-check the value in the stream header.
    """
    tag, size = peek_header(data)

    if tag == TAG_JB01:
        raise DecompressionError(
            "this body uses the JB01 adaptive-Huffman variant (AutoHotkey / AutoIt2), "
            "which this port does not implement"
        )
    if tag not in SUPPORTED_TAGS:
        raise DecompressionError(
            f"unexpected compression tag {tag!r}; expected EA05 or EA06. "
            "Decryption most likely failed, making this data meaningless."
        )

    if expected_size is not None and expected_size != size:
        log.warning(
            "record says %d uncompressed bytes but the stream header says %d; trusting the header",
            expected_size,
            size,
        )

    if size == 0:
        return b""

    literal_bit = LITERAL_BIT[tag]
    bits = _BitReader(data, HEADER_SIZE)
    out = bytearray()
    append = out.append

    while len(out) < size:
        if bits.read(1) == literal_bit:
            append(bits.read(8))
            continue

        offset = bits.read(WINDOW_BITS)
        length = _read_match_len(bits) + MIN_MATCH_LEN

        if offset == 0:
            raise DecompressionError(
                f"zero match offset at output position {len(out)}; the bitstream is corrupt"
            )
        start = len(out) - offset
        if start < 0:
            raise DecompressionError(
                f"match at output position {len(out)} points {offset} bytes back, "
                "before the start of the stream; the bitstream is corrupt"
            )

        # Copy one byte at a time: overlapping matches are how runs get encoded,
        # so a slice copy would be wrong when offset < length.
        for i in range(start, start + length):
            append(out[i])

    if len(out) > size:
        # A final match can overshoot the target; the original writes only the
        # promised number of bytes.
        del out[size:]

    log.debug("decompressed %d bytes from %d (tag %s)", len(out), len(data), tag.decode("ascii"))
    return bytes(out)
