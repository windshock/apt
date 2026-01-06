import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


DEFAULT_BUCKETS = {
    # "상": memory-centric / loader / unpacker-ish (generic)
    "high": {
        "meth_get_eip",
        "pe_detect_tls_callbacks",
        "pe_no_import_table",
        "DetectEncryptedVariants",
        "meth_stackstrings",
        "Suspicious_Process",
        "Sus_CMD_Powershell_Usage",
    },
    # "중": framework/campaign-ish
    "mid": {
        "cobalt_strike_tmp01925d3f",
        "RANSOMWARE",
        "ScanStringsInsocks5systemz",
        "golang_bin_JCorn_CSC846",
    },
    # "하": family-ish / more specific
    "low": {
        "StealcV2",
        "aachum_Stealcv2",
        "win_lumma_generic",
    },
}


def load_buckets(path: str) -> dict[str, set[str]]:
    """
    Load buckets from a JSON file:

    {
      "high": ["rule1", "rule2"],
      "mid": ["rule3"],
      "low": ["rule4"]
    }
    """
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"Invalid buckets JSON (expected object): {p}")
    buckets: dict[str, set[str]] = {}
    for k, v in data.items():
        if not isinstance(k, str) or not isinstance(v, list):
            raise SystemExit(f"Invalid buckets JSON entry: {k} -> {type(v)}")
        buckets[k] = {str(x) for x in v}
    return buckets


def write_template(path: str, rules: set[str]):
    """
    Write a starter buckets JSON with all seen rules in 'other' (user moves them to high/mid/low).
    """
    p = Path(path)
    tpl = {
        "high": sorted(DEFAULT_BUCKETS["high"] & rules),
        "mid": sorted(DEFAULT_BUCKETS["mid"] & rules),
        "low": sorted(DEFAULT_BUCKETS["low"] & rules),
        "other": sorted(rules - (DEFAULT_BUCKETS["high"] | DEFAULT_BUCKETS["mid"] | DEFAULT_BUCKETS["low"])),
    }
    p.write_text(json.dumps(tpl, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def bucket_for_rule(rule: str, buckets: dict[str, set[str]]) -> str:
    for name, rules in buckets.items():
        if rule in rules:
            return name
    return "other"


def main():
    ap = argparse.ArgumentParser(
        description="Profile per-folder YARA matches into high/mid/low buckets and find folders that contain all buckets."
    )
    ap.add_argument("--in", dest="inp", required=True, help="Input yara output: '<rule> <path>' per line")
    ap.add_argument("--root", required=True, help="Root directory whose immediate children are treated as folders")
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument(
        "--group",
        choices=["folder", "sha256"],
        default="folder",
        help="How to group results: per dump folder (default) or by sha256 prefix before first '_'",
    )
    ap.add_argument("--buckets", default="", help="Optional JSON file defining rule buckets (high/mid/low/...).")
    ap.add_argument(
        "--write-buckets-template",
        default="",
        help="Write a starter buckets JSON containing all rules observed in --in and exit.",
    )
    ap.add_argument(
        "--print-all3",
        action="store_true",
        help="Print folders that contain at least one high+mid+low rule.",
    )
    args = ap.parse_args()

    inp = Path(args.inp)
    root = Path(args.root)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    folders = sorted([p.name for p in root.iterdir() if p.is_dir()])
    folder_set = set(folders)
    sha_set = {f.split("_", 1)[0] for f in folders}

    group_rules: dict[str, set[str]] = defaultdict(set)
    group_buckets: dict[str, set[str]] = defaultdict(set)
    seen_rules: set[str] = set()

    for raw in inp.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        rule, path = parts
        seen_rules.add(rule)
        p = Path(path)
        try:
            idx = p.parts.index(root.name)
        except ValueError:
            continue
        if idx + 1 >= len(p.parts):
            continue
        folder = p.parts[idx + 1]
        if folder not in folder_set:
            continue
        if args.group == "sha256":
            group = folder.split("_", 1)[0]
            if group not in sha_set:
                continue
        else:
            group = folder
        group_rules[group].add(rule)

    if args.write_buckets_template:
        write_template(args.write_buckets_template, seen_rules)
        print(f"Wrote buckets template: {args.write_buckets_template}")
        return

    buckets = load_buckets(args.buckets) if args.buckets else DEFAULT_BUCKETS

    for group, rules in group_rules.items():
        for rule in rules:
            group_buckets[group].add(bucket_for_rule(rule, buckets))

    def has_all3(bset: set[str]) -> bool:
        return "high" in bset and "mid" in bset and "low" in bset

    if args.group == "sha256":
        groups = sorted(sha_set)
    else:
        groups = folders

    all3 = [g for g in groups if has_all3(group_buckets.get(g, set()))]

    if args.print_all3:
        print("GROUPS_WITH_HIGH_MID_LOW")
        for g in all3:
            print(g)
        print(f"count {len(all3)}")

    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(
            f,
            fieldnames=[
                "group",
                "has_high",
                "has_mid",
                "has_low",
                "has_all3",
                "rules",
                "buckets",
            ],
        )
        w.writeheader()
        for group in groups:
            rules = sorted(group_rules.get(group, set()))
            bset = sorted(group_buckets.get(group, set()))
            w.writerow(
                {
                    "group": group,
                    "has_high": int("high" in bset),
                    "has_mid": int("mid" in bset),
                    "has_low": int("low" in bset),
                    "has_all3": int(has_all3(set(bset))),
                    "rules": ",".join(rules),
                    "buckets": ",".join(bset),
                }
            )

    print(f"CSV: {out}")


if __name__ == "__main__":
    main()


