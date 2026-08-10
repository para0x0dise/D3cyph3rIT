"""Exception types raised by the extractor."""


class Au3Error(Exception):
    """Base class for all extraction failures."""


class NotFoundError(Au3Error):
    """No embedded AutoIt script could be located in the input."""


class UnsupportedFormatError(Au3Error):
    """The script was located but its format is not handled by this port."""


class DecryptionError(Au3Error):
    """Decryption produced data that failed a structural or checksum check."""


class DecompressionError(Au3Error):
    """The LZSS stream could not be decoded."""


class DetokeniseError(Au3Error):
    """The token stream could not be turned back into source."""
