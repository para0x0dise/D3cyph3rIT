"""Pure-Python extractor for AutoIt3 scripts embedded in compiled executables.

This is a port of the core extraction path of myAutToExe (VB6): locate the
embedded script, decrypt it, decompress it and - for the tokenised EA06
format - turn the token stream back into AutoIt source.
"""

from .errors import Au3Error, NotFoundError, UnsupportedFormatError
from .records import ExtractedFile, ScriptHeader, extract

__all__ = [
    "Au3Error",
    "NotFoundError",
    "UnsupportedFormatError",
    "ExtractedFile",
    "ScriptHeader",
    "extract",
]

__version__ = "0.1.0"
