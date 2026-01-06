import argparse
import csv
import os
import re
from pathlib import Path


PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
EXEC_PROTECT_SET = {PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY}


def parse_protect_from_name(p: Path) -> int | None:
    m = re.search(r"\.([0-9A-Fa-f]{8})\.mdmp$", p.name)
    if not m:
        return None
    try:
        return int(m.group(1), 16)
    except Exception:
        return None


def find_embedded_pe(p: Path, scan_bytes: int) -> tuple[int | None, int | None]:
    """
    Returns (mz_offset, pe_offset) if embedded PE signature found within scan_bytes, else (None, None).
    """
    try:
        with p.open("rb") as f:
            data = f.read(max(0, int(scan_bytes)))
    except Exception:
        return None, None
    if len(data) < 0x100:
        return None, None
    off = 0
    while True:
        i = data.find(b"MZ", off)
        if i < 0:
            return None, None
        if i + 0x40 <= len(data):
            e = int.from_bytes(data[i + 0x3C : i + 0x40], "little", signed=False)
            pe = i + e
            if 0 < e < scan_bytes and pe + 4 <= len(data) and data[pe : pe + 4] == b"PE\x00\x00":
                return i, pe
        off = i + 2


def main():
    ap = argparse.ArgumentParser(
        description="Export Hybrid-Analysis region-split *.mdmp files into simple region_000001.bin files + manifest CSV."
    )
    ap.add_argument("--src", required=True, help="Source dump folder (contains many *.mdmp region files).")
    ap.add_argument("--out", required=True, help="Output directory (will contain region_*.bin + manifest.csv).")
    ap.add_argument(
        "--filter",
        choices=["all", "exec", "rwx", "pe", "exec_or_pe"],
        default="exec_or_pe",
        help="Which regions to export (default: exec_or_pe).",
    )
    ap.add_argument(
        "--pe-scan-bytes",
        type=int,
        default=2_000_000,
        help="How many bytes to scan for embedded PE headers (default: 2,000,000).",
    )
    ap.add_argument("--max-files", type=int, default=0, help="Optional cap on exported regions (0 = no cap).")
    args = ap.parse_args()

    src = Path(args.src)
    out = Path(args.out)
    if not src.exists() or not src.is_dir():
        raise SystemExit(f"--src must be a directory: {src}")
    out.mkdir(parents=True, exist_ok=True)

    manifest = out / "manifest.csv"

    rows: list[dict[str, str]] = []
    exported = 0

    for f in sorted(src.glob("*.mdmp")):
        protect = parse_protect_from_name(f)
        is_exec = protect in EXEC_PROTECT_SET if protect is not None else False
        is_rwx = protect == PAGE_EXECUTE_READWRITE if protect is not None else False
        mz_off, pe_off = find_embedded_pe(f, scan_bytes=int(args.pe_scan_bytes))
        is_pe = mz_off is not None and pe_off is not None

        keep = False
        if args.filter == "all":
            keep = True
        elif args.filter == "exec":
            keep = is_exec
        elif args.filter == "rwx":
            keep = is_rwx
        elif args.filter == "pe":
            keep = is_pe
        elif args.filter == "exec_or_pe":
            keep = is_exec or is_pe

        if not keep:
            continue

        exported += 1
        dst_name = f"region_{exported:06d}.bin"
        dst = out / dst_name

        # Copy bytes (avoid symlinks so output is self-contained)
        dst.write_bytes(f.read_bytes())

        rows.append(
            {
                "region_file": dst_name,
                "src_file": str(f),
                "size": str(dst.stat().st_size),
                "protect_hex": f"0x{protect:08x}" if protect is not None else "",
                "is_exec": "1" if is_exec else "0",
                "is_rwx": "1" if is_rwx else "0",
                "is_pe": "1" if is_pe else "0",
                "mz_offset": "" if mz_off is None else str(mz_off),
                "pe_offset": "" if pe_off is None else str(pe_off),
            }
        )

        if args.max_files and exported >= args.max_files:
            break

    with manifest.open("w", newline="", encoding="utf-8") as mf:
        w = csv.DictWriter(
            mf,
            fieldnames=[
                "region_file",
                "src_file",
                "size",
                "protect_hex",
                "is_exec",
                "is_rwx",
                "is_pe",
                "mz_offset",
                "pe_offset",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    print(f"src {src}")
    print(f"out {out}")
    print(f"exported {exported}")
    print(f"manifest {manifest}")


if __name__ == "__main__":
    # Avoid Windows symlink issues etc; this script is intended to run in Docker/Linux.
    os.environ.setdefault("PYTHONUNBUFFERED", "1")
    main()


