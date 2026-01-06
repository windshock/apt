import argparse
from collections import defaultdict
from pathlib import Path


def parse_rule_folder_hits(inp: Path, root: Path) -> tuple[list[str], dict[str, set[str]]]:
    folders = sorted([p.name for p in root.iterdir() if p.is_dir()])
    folder_set = set(folders)

    rule_to_folders: dict[str, set[str]] = defaultdict(set)

    for raw in inp.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        rule, path = parts
        p = Path(path)
        try:
            idx = p.parts.index(root.name)
        except ValueError:
            continue
        if idx + 1 >= len(p.parts):
            continue
        folder = p.parts[idx + 1]
        if folder in folder_set:
            rule_to_folders[rule].add(folder)

    return folders, rule_to_folders


def greedy_set_cover(universe: set[str], rule_to_folders: dict[str, set[str]]) -> list[tuple[str, int]]:
    uncovered = set(universe)
    picked: list[tuple[str, int]] = []

    # Greedy: pick rule that covers most uncovered folders each step.
    while uncovered:
        best_rule = None
        best_gain = 0
        for rule, covered in rule_to_folders.items():
            gain = len(covered & uncovered)
            if gain > best_gain or (gain == best_gain and best_rule is not None and rule < best_rule):
                best_rule = rule
                best_gain = gain
        if best_rule is None or best_gain == 0:
            break
        picked.append((best_rule, best_gain))
        uncovered -= rule_to_folders[best_rule]
    return picked


def main():
    ap = argparse.ArgumentParser(
        description="Compute a (greedy) minimal YARA rule subset that maximizes folder-level coverage from yara output."
    )
    ap.add_argument("--in", dest="inp", required=True, help="Input file containing yara output lines: '<rule> <path>'")
    ap.add_argument("--root", required=True, help="Root directory whose immediate children are treated as folders.")
    ap.add_argument(
        "--target",
        default="detected",
        choices=["detected", "all"],
        help="Cover target universe: folders detected by any rule ('detected') or all folders under root ('all').",
    )
    ap.add_argument(
        "--max-rules",
        type=int,
        default=0,
        help="Optional cap on number of rules selected (0 = no cap).",
    )
    args = ap.parse_args()

    inp = Path(args.inp)
    root = Path(args.root)
    if not inp.exists():
        raise SystemExit(f"--in not found: {inp}")
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"--root must be an existing directory: {root}")

    folders, rule_to_folders = parse_rule_folder_hits(inp, root)
    detected_any = set()
    for s in rule_to_folders.values():
        detected_any |= set(s)

    if args.target == "detected":
        universe = detected_any
    else:
        universe = set(folders)

    picked = greedy_set_cover(universe, rule_to_folders)
    if args.max_rules and args.max_rules > 0:
        picked = picked[: args.max_rules]

    covered = set()
    for rule, _gain in picked:
        covered |= rule_to_folders.get(rule, set())

    print(f"folders_total {len(folders)}")
    print(f"rules_total {len(rule_to_folders)}")
    print(f"target_universe {args.target} size={len(universe)}")
    print(f"covered {len(covered)}")
    print(f"uncovered {len(set(universe) - covered)}")
    print(f"rules_selected {len(picked)}")
    print("\nRULES (in greedy order):")
    for i, (rule, gain) in enumerate(picked, start=1):
        print(f"{i:02d}\t{rule}\t(+{gain})")


if __name__ == "__main__":
    main()


