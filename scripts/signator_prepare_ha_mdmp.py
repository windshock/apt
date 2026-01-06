import argparse
import os
import re
import shutil
from pathlib import Path

from smda.Disassembler import Disassembler


MDMP_NAME_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{8}\\..*\\.([0-9A-Fa-f]{8})\\..*\\.mdmp$")


def parse_base_addr(mdmp_name: str) -> int | None:
    """
    Try to parse a likely base address from the mdmp chunk filename.
    Example: 00000000-00008572.00000000.282335.01F53000.00000040.mdmp -> 0x01F53000
    """
    parts = mdmp_name.split(".")
    if len(parts) >= 5:
        cand = parts[3]
        if re.fullmatch(r"[0-9A-Fa-f]{8}", cand):
            return int(cand, 16)
    m = MDMP_NAME_RE.match(mdmp_name)
    if m:
        return int(m.group(1), 16)
    return None


def main():
    ap = argparse.ArgumentParser(description="Prepare YARA-Signator datastore from HA mdmp corpus + generate SMDA reports.")
    ap.add_argument("--src", default="/data/ha_dumps_unz", help="Source HA mdmp root (folders containing *.mdmp).")
    ap.add_argument("--datastore", default="/data", help="Datastore root (will create malpedia/, smda_report_output/, yara-output/, VERSIONING.TXT).")
    ap.add_argument("--family", default="win.amadey", help="Family folder name under malpedia/ (default: win.amadey).")
    ap.add_argument("--max-folders", type=int, default=5, help="Max dump folders to include (default: 5).")
    ap.add_argument("--max-files-per-folder", type=int, default=10, help="Max mdmp files per dump folder (default: 10).")
    ap.add_argument("--bitness", type=int, default=64, choices=[32, 64], help="SMDA disassembly bitness (default: 64).")
    args = ap.parse_args()

    src = Path(args.src)
    root = Path(args.datastore)
    family = args.family

    malpedia = root / "malpedia" / family / "ha_mdmp"
    smda_out = root / "smda_report_output"
    yara_out = root / "yara-output"
    root.mkdir(parents=True, exist_ok=True)
    malpedia.mkdir(parents=True, exist_ok=True)
    smda_out.mkdir(parents=True, exist_ok=True)
    yara_out.mkdir(parents=True, exist_ok=True)
    (root / "VERSIONING.TXT").write_text("local\n", encoding="utf-8")

    folders = sorted([p for p in src.iterdir() if p.is_dir()])[: max(0, args.max_folders)]
    print(f"folders_selected: {len(folders)}")

    dis = Disassembler()
    total_files = 0
    total_reports = 0

    for d in folders:
        mdmps = sorted(d.glob("*.mdmp"))[: max(0, args.max_files_per_folder)]
        if not mdmps:
            continue
        out_dir = malpedia / d.name
        out_dir.mkdir(parents=True, exist_ok=True)

        for f in mdmps:
            base = parse_base_addr(f.name) or 0
            # Name file so signator's demo naming pattern would recognize it as a dump.
            # Use 16-hex digits to force 64-bit parsing when needed.
            if args.bitness == 64:
                name = f"dump_0x{base:016x}"
            else:
                name = f"dump_0x{base:08x}"
            dst = out_dir / name

            if not dst.exists():
                shutil.copy2(f, dst)

            buf = dst.read_bytes()
            try:
                report = dis.disassembleBuffer(buf, base, args.bitness)
            except Exception as e:
                print(f"[WARN] smda failed: {dst} ({e})")
                continue

            if not report:
                continue

            report.family = family
            report.version = "ha_mdmp"
            report.filename = dst.name

            out_report = smda_out / (dst.name + ".smda")
            out_report.write_text(
                report.toJSON(indent=1, sort_keys=True), encoding="utf-8"
            )
            total_reports += 1
            total_files += 1

    print(f"files_copied: {total_files}")
    print(f"smda_reports_written: {total_reports}")
    print(f"malpedia_path: {malpedia}")
    print(f"smda_report_output: {smda_out}")
    print(f"yara_output: {yara_out}")


if __name__ == "__main__":
    main()


