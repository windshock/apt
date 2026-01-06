import argparse
import csv
import json
import re
from collections import defaultdict
from pathlib import Path


# Don't use \b boundaries because dump folder names look like:
#   <sha256>_<dumpid>_memory
# and '_' is a "word" char, so \b doesn't match between sha256 and '_'.
SHA256_RE = re.compile(r"(?i)(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])")


def load_buckets(path: str) -> dict[str, set[str]]:
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"Invalid buckets JSON (expected object): {p}")
    out: dict[str, set[str]] = {}
    for k, v in data.items():
        if not isinstance(k, str) or not isinstance(v, list):
            continue
        out[k] = {str(x) for x in v}
    return out


def bucket_for_rule(rule: str, buckets: dict[str, set[str]]) -> str:
    if rule in buckets.get("high", set()):
        return "high"
    if rule in buckets.get("mid", set()):
        return "mid"
    if rule in buckets.get("low", set()):
        return "low"
    return "other"


def extract_sha256(path_str: str) -> str | None:
    m = SHA256_RE.search(path_str)
    if not m:
        return None
    return m.group(0).lower()


def main():
    ap = argparse.ArgumentParser(
        description="Aggregate YARA scan output ('<rule> <path>') by sha256 found in the path and print sha with high+mid+low."
    )
    ap.add_argument("--in", dest="inp", required=True, help="Input yara output: '<rule> <path>' per line")
    ap.add_argument("--buckets", required=True, help="Buckets JSON with keys high/mid/low -> [rule...]")
    ap.add_argument("--out", default="", help="Optional output CSV (sha256-level)")
    ap.add_argument("--print-all3", action="store_true", help="Print sha256 that contain at least one high+mid+low.")
    args = ap.parse_args()

    inp = Path(args.inp)
    buckets = load_buckets(args.buckets)

    sha_rules: dict[str, set[str]] = defaultdict(set)
    sha_buckets: dict[str, set[str]] = defaultdict(set)

    for raw in inp.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        rule, path = parts
        sha = extract_sha256(path)
        if not sha:
            continue
        sha_rules[sha].add(rule)
        sha_buckets[sha].add(bucket_for_rule(rule, buckets))

    def has_all3(bset: set[str]) -> bool:
        return "high" in bset and "mid" in bset and "low" in bset

    all_shas = sorted(sha_buckets.keys())
    all3 = [sha for sha in all_shas if has_all3(sha_buckets.get(sha, set()))]

    if args.print_all3:
        print("SHA256_WITH_HIGH_MID_LOW")
        for sha in all3:
            print(sha)
        print(f"count {len(all3)}")

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(
                f,
                fieldnames=[
                    "sha256",
                    "has_high",
                    "has_mid",
                    "has_low",
                    "has_all3",
                    "rules",
                    "buckets",
                ],
            )
            w.writeheader()
            for sha in all_shas:
                rules = sorted(sha_rules.get(sha, set()))
                bset = sorted(sha_buckets.get(sha, set()))
                w.writerow(
                    {
                        "sha256": sha,
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


