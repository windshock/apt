import argparse
import json
import re
from pathlib import Path


SECTION_RE = re.compile(r"^##\s+(High|Mid|Low)\s*$", re.IGNORECASE)
RULE_LINE_RE = re.compile(r"^\s*-\s+([A-Za-z0-9_][A-Za-z0-9_.-]*)\s*(::.*)?$")


def parse(md_text: str) -> dict[str, list[str]]:
    cur = None
    out: dict[str, set[str]] = {"high": set(), "mid": set(), "low": set()}
    for raw in md_text.splitlines():
        m = SECTION_RE.match(raw.strip())
        if m:
            cur = m.group(1).lower()
            continue
        if not cur:
            continue
        m = RULE_LINE_RE.match(raw)
        if not m:
            continue
        rule = m.group(1).strip()
        if rule:
            out[cur].add(rule)

    return {k: sorted(v) for k, v in out.items()}


def main():
    ap = argparse.ArgumentParser(description="Convert yaraify_rules_classification.md into buckets JSON (high/mid/low).")
    ap.add_argument("--in", dest="inp", required=True, help="Input markdown classification file")
    ap.add_argument("--out", required=True, help="Output JSON path")
    args = ap.parse_args()

    inp = Path(args.inp)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    buckets = parse(inp.read_text(encoding="utf-8", errors="replace"))
    out.write_text(json.dumps(buckets, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"JSON: {out}")
    print(f"counts: high={len(buckets['high'])} mid={len(buckets['mid'])} low={len(buckets['low'])}")


if __name__ == "__main__":
    main()


