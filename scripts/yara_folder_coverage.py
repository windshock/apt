import argparse
import csv
from collections import defaultdict
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(
        description="Aggregate YARA output into folder-level detection. A folder is 'detected' if any file in it matches."
    )
    ap.add_argument("--in", dest="inp", required=True, help="Input file containing yara output lines: '<rule> <path>'")
    ap.add_argument("--root", required=True, help="Root directory whose immediate children are treated as folders.")
    ap.add_argument("--out", required=True, help="Output CSV path.")
    ap.add_argument(
        "--print-undetected",
        action="store_true",
        help="Print undetected folder names to stdout.",
    )
    args = ap.parse_args()

    inp = Path(args.inp)
    root = Path(args.root)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    folders = sorted([p.name for p in root.iterdir() if p.is_dir()])
    folder_set = set(folders)

    folder_rules: dict[str, set[str]] = defaultdict(set)

    for raw in inp.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        rule, path = parts
        p = Path(path)
        # expect: <root>/<folder>/...
        try:
            idx = p.parts.index(root.name)
        except ValueError:
            continue
        if idx + 1 >= len(p.parts):
            continue
        folder = p.parts[idx + 1]
        if folder in folder_set:
            folder_rules[folder].add(rule)

    detected = {f for f in folders if f in folder_rules}
    undetected = [f for f in folders if f not in detected]

    print(f"folders_total {len(folders)}")
    print(f"folders_detected {len(detected)}")
    print(f"detected_pct {((len(detected)/len(folders)*100) if folders else 0):.2f}")
    print(f"folders_undetected {len(undetected)}")

    if args.print_undetected and undetected:
        print("\nUNDETECTED_FOLDERS")
        for f in undetected:
            print(f)

    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["folder", "detected", "matched_rules"])
        w.writeheader()
        for folder in folders:
            rules = sorted(folder_rules.get(folder, set()))
            w.writerow(
                {
                    "folder": folder,
                    "detected": int(folder in detected),
                    "matched_rules": ",".join(rules),
                }
            )

    print(f"CSV: {out}")


if __name__ == "__main__":
    main()


