import argparse
import csv
from collections import defaultdict
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(
        description="Aggregate YARA output (lines: '<rule> <path>') into per-rule unique file match counts."
    )
    ap.add_argument("--in", dest="inp", required=True, help="Input file containing yara output lines.")
    ap.add_argument("--total-files", type=int, default=0, help="Total files scanned (for percentage).")
    ap.add_argument("--out", required=True, help="Output CSV path.")
    args = ap.parse_args()

    inp = Path(args.inp)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    # rule -> set(files)
    hits: dict[str, set[str]] = defaultdict(set)

    for raw in inp.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        # yara output: "<rule_name> <file_path>"
        parts = line.split(maxsplit=1)
        if len(parts) < 2:
            continue
        rule, path = parts[0], parts[1].strip()
        if rule and path:
            hits[rule].add(path)

    total = int(args.total_files) if args.total_files else 0

    rows = []
    for rule, files in hits.items():
        c = len(files)
        pct = (c / total * 100.0) if total > 0 else 0.0
        rows.append((c, pct, rule))

    rows.sort(key=lambda x: (-x[0], x[2]))

    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["rule", "matched_files", "matched_pct"])
        w.writeheader()
        for c, pct, rule in rows:
            w.writerow({"rule": rule, "matched_files": c, "matched_pct": f"{pct:.2f}"})

    print(f"Rules matched: {len(rows)}")
    print(f"CSV: {out}")
    if rows:
        top = rows[:20]
        print("Top rules:")
        for c, pct, rule in top:
            print(f"- {rule}: {c} files ({pct:.2f}%)")


if __name__ == "__main__":
    main()


