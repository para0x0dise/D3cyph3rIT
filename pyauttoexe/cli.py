"""Command-line front end.

The input is only ever read as bytes - it is never loaded, mapped or executed -
so this is safe to point at malware.
"""

import argparse
import json
import logging
import os
import re
import sys
from typing import List, Optional

from .errors import Au3Error
from .records import ExtractedFile, ScriptHeader, extract

log = logging.getLogger("pyauttoexe")

#: Characters Windows forbids in a filename, plus control characters.
_UNSAFE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')

#: Names Windows will not let you create, whatever the extension.
_RESERVED = frozenset(
    ["CON", "PRN", "AUX", "NUL"]
    + [f"COM{i}" for i in range(1, 10)]
    + [f"LPT{i}" for i in range(1, 10)]
)


def _parse_offset(text: str) -> int:
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"{text!r} is not a number; use decimal (1100) or hex (0x44C)"
        ) from None


def _safe_name(name: str, fallback: str) -> str:
    """Reduce an attacker-controlled path to a bare, safe filename.

    Embedded FileInstall paths come from the sample, so they can contain
    traversal sequences or device names. Everything but the basename is
    discarded.
    """
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = _UNSAFE.sub("_", name).strip(" .")
    if not name or name.split(".")[0].upper() in _RESERVED:
        return fallback
    return name[:120]


def _output_name(item: ExtractedFile, stem: str) -> str:
    if item.is_main_script:
        return stem + item.suggested_extension
    fallback = f"{stem}_file{item.index}"
    base = _safe_name(item.compiled_path or item.src_file_inst, fallback)
    if not os.path.splitext(base)[1] and item.suggested_extension:
        base += item.suggested_extension
    return base


def _write(path: str, payload) -> int:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    if isinstance(payload, str):
        # UTF-8 with a BOM, matching what myAutToExe writes so editors and
        # Tidy pick the encoding up correctly.
        with open(path, "w", encoding="utf-8-sig", newline="") as handle:
            handle.write(payload)
    else:
        with open(path, "wb") as handle:
            handle.write(payload)
    return os.path.getsize(path)


def _describe(header: ScriptHeader, files: List[ExtractedFile], written: List[dict]) -> str:
    lines = [
        f"AutoIt {header.subtype} script found at offset 0x{header.offset:X}",
        f"  passphrase hash : {header.passphrase_md5.hex()}"
        + ("  (password protected)" if header.is_password_protected else ""),
        f"  embedded files  : {len(files)}",
        "",
    ]
    for item, record in zip(files, written):
        check = {True: "ok", False: "FAILED", None: "n/a"}[item.checksum_ok]
        lines.append(
            f"  #{item.index} {item.src_file_inst!r}"
            + ("  [main script]" if item.is_main_script else "")
        )
        lines.append(f"       compiled from : {item.compiled_path}")
        lines.append(
            f"       {len(item.data)} bytes"
            + (" (decompressed)" if item.was_compressed else " (stored)")
            + f", adler32 {check}"
        )
        for path in record["written"]:
            lines.append(f"       -> {path}")
    return "\n".join(lines)


def run(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="au3extract",
        description=(
            "Extract the embedded AutoIt3 script from a compiled executable. "
            "Supports the EA05 (AutoIt 3.2.x) and EA06 (AutoIt 3.26+) formats. "
            "The input is only ever read, never executed."
        ),
        epilog="UPX-packed inputs are not handled; unpack them first with 'upx -d'.",
    )
    parser.add_argument("input", help="compiled AutoIt executable, .a3x, or raw blob")
    parser.add_argument(
        "-o",
        "--output-dir",
        metavar="DIR",
        help="where to write extracted files (default: next to the input)",
    )
    parser.add_argument(
        "--offset",
        type=_parse_offset,
        metavar="N",
        help="parse at this offset instead of scanning for the signature",
    )
    parser.add_argument(
        "--no-detokenise",
        action="store_true",
        help="write the raw EA06 token stream instead of AutoIt source",
    )
    parser.add_argument(
        "--keep-intermediates",
        action="store_true",
        help="also write the compressed form of each body, for debugging",
    )
    parser.add_argument(
        "--ignore-checksum",
        action="store_true",
        help="continue even if the Adler32 check fails",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print the main script to stdout instead of writing files",
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON report")
    parser.add_argument(
        "-v", "--verbose", action="count", default=0, help="log each step; repeat for more"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level={0: logging.WARNING, 1: logging.INFO}.get(args.verbose, logging.DEBUG),
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    try:
        with open(args.input, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 1

    try:
        header, files = extract(
            data,
            offset=args.offset,
            ignore_checksum=args.ignore_checksum,
            do_detokenise=not args.no_detokenise,
            keep_intermediates=args.keep_intermediates,
        )
    except Au3Error as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.stdout:
        main = next((f for f in files if f.is_main_script), None)
        if main is None:
            print("error: no main script found", file=sys.stderr)
            return 1
        payload = main.text
        if payload is None:
            sys.stdout.buffer.write(main.data)
        else:
            sys.stdout.write(payload)
        return 0

    out_dir = args.output_dir or (os.path.dirname(os.path.abspath(args.input)))
    stem = os.path.splitext(os.path.basename(args.input))[0] or "script"

    written: List[dict] = []
    for item in files:
        record = {"index": item.index, "written": []}
        if not item.data:
            log.info("record #%d (%r) is empty, nothing to write", item.index, item.src_file_inst)
            written.append(record)
            continue

        path = os.path.join(out_dir, _output_name(item, stem))
        payload = item.text if item.text is not None else item.data
        size = _write(path, payload)
        record["written"].append(path)
        log.info("wrote %s (%d bytes)", path, size)

        if args.keep_intermediates and item.compressed_body:
            raw_path = os.path.splitext(path)[0] + ".compressed"
            _write(raw_path, item.compressed_body)
            record["written"].append(raw_path)
        if args.keep_intermediates and item.text is not None:
            tok_path = os.path.splitext(path)[0] + ".tok"
            _write(tok_path, item.data)
            record["written"].append(tok_path)

        written.append(record)

    if args.json:
        print(
            json.dumps(
                {
                    "input": os.path.abspath(args.input),
                    "offset": header.offset,
                    "subtype": header.subtype,
                    "passphrase_md5": header.passphrase_md5.hex(),
                    "password_protected": header.is_password_protected,
                    "files": [
                        {
                            "index": item.index,
                            "marker": item.src_file_inst,
                            "compiled_path": item.compiled_path,
                            "size": len(item.data),
                            "compressed": item.was_compressed,
                            "checksum_ok": item.checksum_ok,
                            "main_script": item.is_main_script,
                            "detokenised": item.detokenised is not None,
                            "written": record["written"],
                        }
                        for item, record in zip(files, written)
                    ],
                },
                indent=2,
            )
        )
    else:
        print(_describe(header, files, written))

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
