"""Find where the embedded AutoIt script starts inside a file.

myAutToExe's ``FindStartOfScript`` scans the whole file for a 16-byte magic
followed by ``AU3!``. That plain scan handles PE executables, raw overlays and
``.a3x`` blobs alike, which is why this port leads with it rather than with PE
parsing. The Vidar sample in ``testSamples/`` is not a PE at all - it is a bare
blob with the script sitting at offset 0x44C - so PE parsing is strictly a
fallback here.
"""

import struct
from typing import List, NamedTuple, Optional

from .errors import NotFoundError

#: The 16-byte marker that precedes every compiled AutoIt3 script.
#: From ``DeCompilerConfig.bas`` and confirmed verbatim in ``Au3-Extract.au3``.
AU3_SIGNATURE = bytes.fromhex("A3484BBE986C4AA9994C530A86D6487D")

AU3_TYPE = b"AU3!"
SUBTYPE_EA05 = b"EA05"
SUBTYPE_EA06 = b"EA06"
KNOWN_SUBTYPES = (SUBTYPE_EA05, SUBTYPE_EA06)

SIGNATURE_SIZE = len(AU3_SIGNATURE)


class Candidate(NamedTuple):
    """A possible script start.

    ``offset`` points at the first byte of the 16-byte signature, which is what
    the record parser expects.
    """

    offset: int
    subtype: Optional[bytes]
    source: str

    @property
    def subtype_name(self) -> str:
        return self.subtype.decode("ascii") if self.subtype else "unknown"


def _read_subtype(data: bytes, sig_offset: int) -> Optional[bytes]:
    """Peek at the 4 bytes after ``AU3!`` and return them if they look sane."""
    start = sig_offset + SIGNATURE_SIZE + len(AU3_TYPE)
    subtype = data[start : start + 4]
    return subtype if len(subtype) == 4 else None


def find_all(data: bytes) -> List[Candidate]:
    """Every ``signature + AU3!`` occurrence, in file order.

    Signature-only matches (AutoIt2-era, no type tag) are reported too, since
    myAutToExe falls back to them, but they sort after the tagged hits.
    """
    tagged: List[Candidate] = []
    untagged: List[Candidate] = []

    pos = data.find(AU3_SIGNATURE)
    while pos != -1:
        after = pos + SIGNATURE_SIZE
        if data[after : after + len(AU3_TYPE)] == AU3_TYPE:
            tagged.append(Candidate(pos, _read_subtype(data, pos), "signature+AU3!"))
        else:
            untagged.append(Candidate(pos, None, "signature only"))
        pos = data.find(AU3_SIGNATURE, pos + 1)

    return tagged + untagged


def check_footer(data: bytes) -> Optional[bytes]:
    """Return the subtype advertised by the trailing ``AU3!EA0x`` marker.

    Ports ``TestForV3_26`` / ``TestForV3_2``, which look at the last 8 bytes.
    This does not give an offset, only a strong hint about the format, and is
    used to disambiguate when several signature hits are present.
    """
    if len(data) < 8:
        return None
    tail = data[-8:]
    if tail[:4] == AU3_TYPE and tail[4:8] in KNOWN_SUBTYPES:
        return tail[4:8]
    return None


def find_resource_script(data: bytes) -> Optional[int]:
    """Look for a UTF-16LE ``SCRIPT\\0`` name in the PE resource directory.

    AutoIt 3.3+ can embed the script as a PE resource rather than as an
    overlay. This mirrors ``TestForV3_3``. Returns the offset of the name
    string, or ``None``; it is only a hint that a resource-embedded script
    exists, so callers still scan for the real signature.
    """
    bounds = _resource_bounds(data)
    if bounds is None:
        return None
    start, size = bounds
    needle = "SCRIPT\0".encode("utf-16-le")
    pos = data.find(needle, start, start + size)
    return pos if pos != -1 else None


def _resource_bounds(data: bytes):
    """Raw offset and size of the PE resource directory, if this is a PE."""
    try:
        if data[:2] != b"MZ":
            return None
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            return None

        coff = e_lfanew + 4
        num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        # Data directories start after the optional header's fixed part, which
        # differs between PE32 (0x60) and PE32+ (0x70).
        dd = opt + (0x70 if magic == 0x20B else 0x60)
        # Directory index 2 is the resource table.
        res_rva, res_size = struct.unpack_from("<II", data, dd + 2 * 8)
        if not res_rva or not res_size:
            return None

        sections = opt + opt_size
        for i in range(num_sections):
            sec = sections + i * 40
            va = struct.unpack_from("<I", data, sec + 12)[0]
            raw_size = struct.unpack_from("<I", data, sec + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, sec + 20)[0]
            if va <= res_rva < va + max(raw_size, 1):
                return raw_ptr + (res_rva - va), min(res_size, raw_size)
    except (struct.error, IndexError):
        return None
    return None


def find_script_start(data: bytes, offset: Optional[int] = None) -> Candidate:
    """Pick the offset the record parser should start from.

    With an explicit ``offset`` this just validates and describes it. Otherwise
    it scans, and when several candidates exist it prefers the one whose
    subtype agrees with the file's trailing marker.
    """
    if offset is not None:
        if offset < 0 or offset >= len(data):
            raise NotFoundError(f"offset 0x{offset:X} is outside the file")
        if data[offset : offset + SIGNATURE_SIZE] != AU3_SIGNATURE:
            # Trust the user, but say so - they may be pointing at a script
            # whose signature was patched out.
            return Candidate(offset, _read_subtype(data, offset), "user-supplied offset")
        return Candidate(offset, _read_subtype(data, offset), "user-supplied offset")

    candidates = find_all(data)
    if not candidates:
        raise NotFoundError(
            "no AutoIt signature found. The file may be packed (try 'upx -d'), "
            "encrypted, or not a compiled AutoIt executable at all."
        )

    footer = check_footer(data)
    if footer is not None:
        for candidate in candidates:
            if candidate.subtype == footer:
                return candidate

    for candidate in candidates:
        if candidate.subtype in KNOWN_SUBTYPES:
            return candidate

    return candidates[0]
