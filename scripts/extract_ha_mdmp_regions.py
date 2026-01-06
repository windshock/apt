import argparse
import os
import re
from pathlib import Path


PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
EXEC_PROTECT_SET = {PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}


def _parse_protect_from_name(p: Path) -> int | None:
    """
    HA "memory dump unzip" folders contain many *.mdmp files whose filename ends with
    ".<8hex>.mdmp" where the last 8-hex token matches Windows PAGE_* protection flags
    (e.g., 0x20 PAGE_EXECUTE_READ, 0x40 PAGE_EXECUTE_READWRITE, 0x04 PAGE_READWRITE).
    """
    m = re.search(r"\.([0-9A-Fa-f]{8})\.mdmp$", p.name)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except Exception:
        return None


def _find_embedded_pe(p: Path, scan_bytes: int) -> tuple[bool, int | None, int | None]:
    """
    Heuristic: search within the first scan_bytes for an embedded PE header:
      - find 'MZ' at some offset
      - read e_lfanew at (offset + 0x3c)
      - verify 'PE\\0\\0' at (offset + e_lfanew)

    Returns: (found, mz_offset, pe_offset)
    """
    try:
        with p.open("rb") as f:
            data = f.read(max(0, int(scan_bytes)))
    except Exception:
        return False, None, None

    if len(data) < 0x100:
        return False, None, None

    off = 0
    while True:
        i = data.find(b"MZ", off)
        if i < 0:
            return False, None, None
        # Need at least DOS header fields
        if i + 0x40 <= len(data):
            e_lfanew = int.from_bytes(data[i + 0x3C : i + 0x40], "little", signed=False)
            # Conservative sanity bound: within scan window, not too tiny/huge
            if 0 < e_lfanew < scan_bytes:
                pe = i + e_lfanew
                if pe + 4 <= len(data) and data[pe : pe + 4] == b"PE\x00\x00":
                    return True, i, pe
        off = i + 2


def _is_pe_header_region(p: Path, scan_bytes: int, mode: str) -> bool:
    """
    mode:
      - start: require the region starts with a PE ('MZ' at offset 0)
      - anywhere: allow embedded PE headers (common in HA region blobs)
    """
    if mode == "start":
        found, mz, _pe = _find_embedded_pe(p, scan_bytes=scan_bytes)
        return bool(found and mz == 0)
    # default: anywhere
    found, _mz, _pe = _find_embedded_pe(p, scan_bytes=scan_bytes)
    return bool(found)


def _safe_link_or_copy(src: Path, dst: Path, link: bool):
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() or dst.is_symlink():
        dst.unlink()
    if link:
        os.symlink(src, dst)
    else:
        # Avoid pulling in shutil just for a single call; use pathlib
        dst.write_bytes(src.read_bytes())


def main():
    ap = argparse.ArgumentParser(
        description="Select high-signal regions from HA 'mdmp' region files (PE header regions + executable/RWX regions)."
    )
    ap.add_argument("--src", required=True, help="Source folder containing many *.mdmp region files.")
    ap.add_argument("--out", required=True, help="Output folder (will create dlllist/ and malfind/ subfolders).")
    ap.add_argument("--rwx-only", action="store_true", help="Only include PAGE_EXECUTE_READWRITE (0x40) regions.")
    ap.add_argument(
        "--pe-mode",
        choices=["anywhere", "start"],
        default="anywhere",
        help="How to detect PE header regions: embedded anywhere (default) or only if region starts with MZ.",
    )
    ap.add_argument(
        "--pe-scan-bytes",
        type=int,
        default=2_000_000,
        help="How many bytes to scan for embedded PE headers (default: 2,000,000).",
    )
    ap.add_argument("--link", action="store_true", help="Symlink outputs to originals (default).")
    ap.add_argument("--copy", action="store_true", help="Copy outputs instead of symlinking.")
    args = ap.parse_args()

    src = Path(args.src)
    out = Path(args.out)
    if not src.exists() or not src.is_dir():
        raise SystemExit(f"--src must be an existing directory: {src}")

    if args.copy and args.link:
        raise SystemExit("Choose only one of --link or --copy")
    link = True if not args.copy else False

    dll_out = out / "dlllist"
    mal_out = out / "malfind"
    dll_out.mkdir(parents=True, exist_ok=True)
    mal_out.mkdir(parents=True, exist_ok=True)

    total = 0
    pe_cnt = 0
    exec_cnt = 0

    for f in sorted(src.glob("*.mdmp")):
        total += 1
        protect = _parse_protect_from_name(f)

        is_exec = False
        if protect is not None:
            if args.rwx_only:
                is_exec = protect == PAGE_EXECUTE_READWRITE
            else:
                # Windows PAGE_* protections are enumerated values, not bitmasks.
                is_exec = protect in EXEC_PROTECT_SET

        is_pe = _is_pe_header_region(f, scan_bytes=int(args.pe_scan_bytes), mode=str(args.pe_mode))

        # "loaded module" proxy: PE header region
        if is_pe:
            pe_cnt += 1
            _safe_link_or_copy(f, dll_out / f.name, link=link)

        # "rwx/private executable region" proxy: executable protection
        if is_exec:
            exec_cnt += 1
            _safe_link_or_copy(f, mal_out / f.name, link=link)

    print(f"Selected from: {src}")
    print(f"Out: {out}")
    print(f"Total region files: {total}")
    print(f"PE header regions (dlllist/): {pe_cnt}")
    print(f"Executable regions (malfind/): {exec_cnt}")


if __name__ == "__main__":
    main()


