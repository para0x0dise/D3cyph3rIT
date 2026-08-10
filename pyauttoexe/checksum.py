"""Adler32 as myAutToExe computes it.

``CRC_Adler32.bas`` returns the two 16-bit halves as ``H16(high) & H16(low)``,
i.e. the conventional ``(high << 16) | low`` packing. Python's
``zlib.adler32`` produces the same value, so this is a thin wrapper that exists
to document the equivalence and to keep the call sites readable.

The value stored in a FILE record covers the *decrypted but still compressed*
body, so a match proves decryption worked - it says nothing about
decompression.
"""

import zlib

MOD_ADLER = 65521


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def adler32_reference(data: bytes) -> int:
    """Literal transcription of ``CRC_Adler32.bas``, used to test the fast path."""
    low = 1
    high = 0
    for byte in data:
        low = (low + byte) % MOD_ADLER
        high = (high + low) % MOD_ADLER
    return ((high << 16) | low) & 0xFFFFFFFF
