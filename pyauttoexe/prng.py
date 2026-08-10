"""The two pseudo-random generators AutoIt uses as keystream sources.

myAutToExe calls these through ``data/RanRot_MT.dll``; ``RanRot_MT.def`` maps the
exports it imports onto the underlying implementations::

    MT_GetI8 = genrand_int31
    MT_Init  = init_genrand
    RanRot_Init
    RanRot_GetI8

``MT_*`` is stock MT19937 (``mt19937ar.c``) and drives the EA05 format.
``RanRot_*`` is Agner Fog's RANROT type B (``RANROTB.CPP``) and drives EA06.

Both expose ``next_byte()``, which yields one keystream byte. The consumer XORs
it with the ciphertext.
"""

import struct
from typing import Iterator, List

UINT32_MASK = 0xFFFFFFFF


class MT19937:
    """Stock MT19937, matching ``mt19937ar.c`` as shipped with myAutToExe.

    Used for the EA05 (AutoIt 3.2.x) format. The keystream byte is the low byte
    of ``genrand_int31()``, i.e. ``(genrand_int32() >> 1) & 0xFF``.
    """

    N = 624
    M = 397
    MATRIX_A = 0x9908B0DF
    UPPER_MASK = 0x80000000
    LOWER_MASK = 0x7FFFFFFF

    __slots__ = ("_mt", "_mti")

    def __init__(self, seed: int):
        self._mt: List[int] = [0] * self.N
        self._mti = self.N + 1
        self.init_genrand(seed)

    def init_genrand(self, seed: int) -> None:
        mt = self._mt
        mt[0] = seed & UINT32_MASK
        for i in range(1, self.N):
            # mt[i] = 1812433253 * (mt[i-1] ^ (mt[i-1] >> 30)) + i
            mt[i] = (1812433253 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & UINT32_MASK
        self._mti = self.N

    def genrand_int32(self) -> int:
        mt = self._mt
        if self._mti >= self.N:
            for kk in range(self.N - self.M):
                y = (mt[kk] & self.UPPER_MASK) | (mt[kk + 1] & self.LOWER_MASK)
                mt[kk] = mt[kk + self.M] ^ (y >> 1) ^ (self.MATRIX_A if y & 1 else 0)
            for kk in range(self.N - self.M, self.N - 1):
                y = (mt[kk] & self.UPPER_MASK) | (mt[kk + 1] & self.LOWER_MASK)
                mt[kk] = (
                    mt[kk + (self.M - self.N)] ^ (y >> 1) ^ (self.MATRIX_A if y & 1 else 0)
                )
            y = (mt[self.N - 1] & self.UPPER_MASK) | (mt[0] & self.LOWER_MASK)
            mt[self.N - 1] = mt[self.M - 1] ^ (y >> 1) ^ (self.MATRIX_A if y & 1 else 0)
            self._mti = 0

        y = mt[self._mti]
        self._mti += 1

        y ^= y >> 11
        y ^= (y << 7) & 0x9D2C5680
        y ^= (y << 15) & 0xEFC60000
        y ^= y >> 18
        return y & UINT32_MASK

    def genrand_int31(self) -> int:
        return self.genrand_int32() >> 1

    def next_byte(self) -> int:
        return self.genrand_int31() & 0xFF


def _rotl32(value: int, count: int) -> int:
    count &= 31
    if count == 0:
        return value & UINT32_MASK
    return ((value << count) | (value >> (32 - count))) & UINT32_MASK


class RanRotB:
    """Agner Fog's RANROT type B, as built into ``RanRot_MT.dll``.

    Lagged-Fibonacci with bit rotation::

        X[n] = (rotl(X[n-j], R1) + rotl(X[n-k], R2)) mod 2^32

    Parameters come from ``randomC.H``: ``KK=17, JJ=10, R1=13, R2=9``.

    Two details matter for byte-exact output and are easy to miss:

    * The seed is truncated to 16 bits before ``RandomInit``. myAutToExe's
      ``RanRot_Init`` does ``initSeed And 65535`` and notes this mirrors what the
      AutoIt 3.4.6 binary does (``MOVZX EAX, [WORD ESP+8]``).
    * ``I8Random`` calls ``Random()`` **twice** and only uses the second result.
    """

    KK = 17
    JJ = 10
    R1 = 13
    R2 = 9

    __slots__ = ("_buf", "_p1", "_p2")

    def __init__(self, seed: int):
        self._buf: List[int] = [0] * self.KK
        self._p1 = 0
        self._p2 = self.JJ
        self.random_init(seed)

    def random_init(self, seed: int) -> None:
        # RanRot_Init() truncates to 16 bits before handing off to RandomInit().
        s = seed & 0xFFFF
        buf = self._buf
        for i in range(self.KK):
            s = (s * 2891336453 + 1) & UINT32_MASK
            buf[i] = s

        self._p1 = 0
        self._p2 = self.JJ

        # RandomInit() discards nine outputs to mix the state.
        for _ in range(9):
            self.random()

    def random_uint32(self) -> int:
        """One raw 32-bit step of the generator."""
        buf = self._buf
        x = (_rotl32(buf[self._p2], self.R1) + _rotl32(buf[self._p1], self.R2)) & UINT32_MASK
        buf[self._p1] = x

        self._p1 -= 1
        if self._p1 < 0:
            self._p1 = self.KK - 1
        self._p2 -= 1
        if self._p2 < 0:
            self._p2 = self.KK - 1

        return x

    def random(self) -> float:
        """A double in [0, 1), built exactly the way the C++ does it.

        The C++ writes the 32-bit state into the mantissa of an IEEE754 double
        whose exponent is fixed at 1.0, then subtracts 1.0. Reproducing this bit
        pattern rather than dividing by 2**32 matters: the two differ in the low
        mantissa bits, which is enough to change the occasional keystream byte.
        """
        x = self.random_uint32()
        lo = (x << 20) & UINT32_MASK
        hi = (x >> 12) | 0x3FF00000
        return struct.unpack("<d", struct.pack("<II", lo, hi))[0] - 1.0

    def next_byte(self) -> int:
        """``I8Random()``: burn one value, scale the next into a byte."""
        self.random()
        result = int(self.random() * 256.0)
        return 0xFF if result >= 0x100 else result


def mt_keystream(seed: int, length: int) -> bytes:
    gen = MT19937(seed)
    return bytes(gen.next_byte() for _ in range(length))


def ranrot_keystream(seed: int, length: int) -> bytes:
    gen = RanRotB(seed)
    return bytes(gen.next_byte() for _ in range(length))


def iter_mt_bytes(seed: int) -> Iterator[int]:
    gen = MT19937(seed)
    while True:
        yield gen.next_byte()


def iter_ranrot_bytes(seed: int) -> Iterator[int]:
    gen = RanRotB(seed)
    while True:
        yield gen.next_byte()
