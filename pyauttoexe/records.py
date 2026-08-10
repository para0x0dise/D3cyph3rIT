"""Parse the script header and walk the embedded FILE records.

Layout, as implemented by ``Decompile.bas``::

    16  AutoIt signature
     4  "AU3!"
     4  subtype, "EA05" or "EA06"
    16  MD5 hash of the compile passphrase

then a run of records, each::

     4  "FILE", encrypted
     ?  SrcFile_FileInst   (encrypted, length-prefixed)
     ?  CompiledPathName   (encrypted, length-prefixed)
     1  compressed flag
     4  compressed size    ^ size key
     4  uncompressed size  ^ size key
     4  Adler32 of body    ^ checksum key
    16  two FILETIMEs, as four u32 halves
     ?  body               (encrypted, `compressed size` bytes)

The run ends when the 4-byte tag stops decrypting to ``FILE``.
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional

from . import lzss
from .checksum import adler32
from .crypto import FieldReader, FormatKeys, decrypt, keys_for
from .detokenise import detokenise, looks_like_token_stream
from .errors import Au3Error, DecryptionError
from .locate import AU3_TYPE, SIGNATURE_SIZE, Candidate, find_script_start

log = logging.getLogger(__name__)

#: Marker strings that identify the record holding the main script, as opposed
#: to a FileInstall() resource. From the chain of comparisons in Decompile.bas.
MAIN_SCRIPT_MARKERS = frozenset(
    {
        ">>>AUTOIT SCRIPT<<<",
        ">>>AUTOIT NO CMDEXECUTE<<<",
        ">AUTOIT UNICODE SCRIPT<",
        ">AUTOIT SCRIPT<",
    }
)

#: A record's body is capped at this to keep a desynchronised parse from trying
#: to allocate absurd amounts. Real scripts are far smaller.
MAX_REASONABLE_BODY = 256 * 1024 * 1024


@dataclass
class ScriptHeader:
    offset: int
    subtype: str
    passphrase_md5: bytes
    keys: FormatKeys

    @property
    def is_password_protected(self) -> bool:
        """EA05 stores the MD5 of the compile passphrase; all-zero means none.

        EA06 does not gate extraction on the passphrase at all, because its body
        key derivation discards the hash entirely.
        """
        return self.keys.name == "EA05" and any(self.passphrase_md5)


@dataclass
class ExtractedFile:
    """One decrypted, decompressed member of the archive."""

    index: int
    src_file_inst: str
    compiled_path: str
    data: bytes
    was_compressed: bool
    declared_size: int
    checksum_ok: Optional[bool]
    is_main_script: bool
    is_tokenised: bool
    detokenised: Optional[str] = field(default=None, repr=False)

    #: The body after decryption but before decompression. Only kept when the
    #: caller asks for it, since it roughly doubles peak memory.
    compressed_body: Optional[bytes] = field(default=None, repr=False)

    @property
    def text(self) -> Optional[str]:
        """The script source, if we got as far as producing it."""
        return self.detokenised

    @property
    def suggested_extension(self) -> str:
        if self.detokenised is not None:
            return ".au3"
        if self.is_tokenised:
            return ".tok"
        if self.is_main_script:
            return ".au3"
        return ""


def _derive_body_key(md5_hash: bytes, keys: FormatKeys) -> int:
    """Seed for the body keystream.

    EA05 sums the 16 hash bytes and adds 0x22AF, so a passphrase actually
    changes the key. EA06 *multiplies* into an accumulator that starts at zero
    (``Decompile.bas`` line 1140), so the product is always zero and the key
    collapses to the bare constant. The comment there flags it as possibly a
    bug; either way it has to be reproduced, and it is why EA06 scripts extract
    without knowing the passphrase.
    """
    if keys.is_new:
        return keys.body
    return (sum(md5_hash) + keys.body) & 0xFFFFFFFF


def parse_header(data: bytes, candidate: Candidate) -> ScriptHeader:
    offset = candidate.offset
    reader = FieldReader(data, offset)

    reader.skip(SIGNATURE_SIZE)
    type_tag = reader.read_exact(4, "type tag")
    if type_tag != AU3_TYPE:
        raise Au3Error(
            f"expected {AU3_TYPE!r} at offset 0x{offset + SIGNATURE_SIZE:X}, found {type_tag!r}"
        )

    subtype = reader.read_exact(4, "subtype")
    keys = keys_for(subtype)
    passphrase_md5 = reader.read_exact(16, "passphrase hash")

    log.debug(
        "header at 0x%X: subtype=%s md5=%s", offset, subtype.decode("ascii"), passphrase_md5.hex()
    )
    return ScriptHeader(
        offset=offset,
        subtype=subtype.decode("ascii"),
        passphrase_md5=passphrase_md5,
        keys=keys,
    )


def _body_start(header: ScriptHeader) -> int:
    return header.offset + SIGNATURE_SIZE + 4 + 4 + 16


def read_records(
    data: bytes,
    header: ScriptHeader,
    *,
    ignore_checksum: bool = False,
    decompress: bool = True,
    keep_intermediates: bool = False,
    max_records: int = 4096,
) -> List[ExtractedFile]:
    keys = header.keys
    reader = FieldReader(data, _body_start(header), keys)
    body_key = _derive_body_key(header.passphrase_md5, keys)
    log.debug("body keystream seed: 0x%X", body_key)

    results: List[ExtractedFile] = []

    for index in range(1, max_records + 1):
        if reader.remaining < 4:
            break

        tag_offset = reader.position
        tag = decrypt(reader.read_exact(4, "FILE tag"), keys.file_tag, keys.is_new)
        if tag != b"FILE":
            if index == 1:
                raise DecryptionError(
                    f"expected an encrypted 'FILE' tag at offset 0x{tag_offset:X} but decrypted "
                    f"{tag!r}. The subtype may be wrong, or the script data may be corrupted "
                    f"(some packers, e.g. Armadillo, damage it in place - dumping from memory helps)."
                )
            log.debug("record run ended at 0x%X (tag decrypted to %r)", tag_offset, tag)
            break

        src_file_inst = reader.encrypted_string(*keys.src_file_inst)
        compiled_path = reader.encrypted_string(*keys.compiled_path)

        was_compressed = bool(reader.uint8())
        compressed_size = reader.uint32() ^ keys.size
        uncompressed_size = reader.uint32() ^ keys.size
        stored_checksum = reader.uint32() ^ keys.checksum

        # Two FILETIMEs, stored high-half first. Not used for extraction.
        reader.skip(16)

        if compressed_size < 0 or compressed_size > MAX_REASONABLE_BODY:
            raise DecryptionError(
                f"record #{index} claims a {compressed_size} byte body, which is not credible; "
                "decryption has desynchronised"
            )

        log.debug(
            "record #%d: %r from %r, %s, %d -> %d bytes",
            index,
            src_file_inst,
            compiled_path,
            "compressed" if was_compressed else "stored",
            compressed_size,
            uncompressed_size,
        )

        encrypted = reader.read(compressed_size)
        if len(encrypted) != compressed_size:
            log.warning(
                "record #%d is truncated: %d of %d body bytes present",
                index,
                len(encrypted),
                compressed_size,
            )

        body = decrypt(encrypted, body_key, keys.is_new)

        checksum_ok: Optional[bool] = None
        if stored_checksum:
            actual = adler32(body)
            checksum_ok = actual == stored_checksum
            if not checksum_ok:
                message = (
                    f"record #{index}: Adler32 mismatch, stored 0x{stored_checksum:08X} but "
                    f"computed 0x{actual:08X}"
                )
                if ignore_checksum:
                    log.warning("%s (continuing anyway)", message)
                else:
                    raise DecryptionError(
                        message
                        + ". Decryption likely failed or the script data is damaged. "
                        "Re-run with --ignore-checksum to extract anyway."
                    )
            else:
                log.debug("record #%d: Adler32 0x%08X OK", index, actual)

        compressed_body = body if keep_intermediates else None

        if was_compressed and decompress and body:
            body = lzss.decompress(body, expected_size=uncompressed_size)

        # A record can carry a main-script marker and still be empty: AutoIt
        # uses zero-length records such as '>>>AUTOIT NO CMDEXECUTE<<<' purely
        # as compiler flags, so require actual content before calling it the
        # main script.
        is_main = bool(body) and src_file_inst in MAIN_SCRIPT_MARKERS

        results.append(
            ExtractedFile(
                index=index,
                src_file_inst=src_file_inst,
                compiled_path=compiled_path,
                data=body,
                was_compressed=was_compressed,
                declared_size=uncompressed_size,
                checksum_ok=checksum_ok,
                is_main_script=is_main,
                is_tokenised=keys.is_new and is_main,
                compressed_body=compressed_body,
            )
        )

    if not results:
        raise DecryptionError("no FILE records could be read from the script region")

    if not any(item.is_main_script for item in results):
        # Nothing carried a recognised marker; fall back to the first record
        # that actually has content.
        for item in results:
            if item.data:
                item.is_main_script = True
                item.is_tokenised = keys.is_new
                break

    return results


def extract(
    data: bytes,
    *,
    offset: Optional[int] = None,
    ignore_checksum: bool = False,
    decompress: bool = True,
    do_detokenise: bool = True,
    keep_intermediates: bool = False,
):
    """Full pipeline: locate, parse, decrypt, decompress, de-tokenise.

    Returns ``(header, files)``.
    """
    candidate = find_script_start(data, offset)
    log.debug("script start 0x%X via %s", candidate.offset, candidate.source)

    header = parse_header(data, candidate)
    files = read_records(
        data,
        header,
        ignore_checksum=ignore_checksum,
        decompress=decompress,
        keep_intermediates=keep_intermediates,
    )

    if do_detokenise and decompress:
        for item in files:
            # EA06 marks the main script as tokenised, but FileInstall'd .tok
            # files show up too, so sniff rather than trust the flag alone.
            if item.is_tokenised or looks_like_token_stream(item.data):
                try:
                    item.detokenised = detokenise(item.data)
                    item.is_tokenised = True
                except Au3Error as exc:
                    log.warning("record #%d: de-tokenising failed: %s", item.index, exc)

    return header, files
