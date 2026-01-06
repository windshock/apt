import argparse
import csv
import logging
import subprocess
import time
from pathlib import Path


def iter_files(target: Path):
    if target.is_file():
        yield target
        return
    for p in target.rglob("*"):
        if p.is_file():
            yield p


def iter_from_list(list_file: Path, base_dir: Path | None):
    """
    Read a file containing one path per line.
    - Ignores blank lines and comments starting with '#'
    - If a line is a relative path and base_dir is provided, it will be resolved relative to base_dir.
    """
    for raw in list_file.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        p = Path(line)
        if not p.is_absolute() and base_dir is not None:
            p = base_dir / p
        yield p


def _parse_yara_matches(stdout: str) -> list[str]:
    """
    Default yara output is typically: "<rule_name> <file_path>"
    We conservatively take the first token on each non-empty line as the rule name.
    """
    matches: list[str] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        rule = s.split(maxsplit=1)[0]
        if rule:
            matches.append(rule)
    return matches


def run_yara(
    rules: str,
    file_path: str,
    timeout_s: float | None,
    fast_scan: bool,
) -> tuple[bool, list[str], str | None]:
    """
    Returns:
      matched(bool), matches([rule_name...]), error(str|None)
    """
    cmd = ["yara"]
    if fast_scan:
        cmd.append("-f")
    # Prefer YARA's own timeout (-a) so it can abort matching internally.
    # Keep a slightly larger subprocess timeout as a safety net.
    subprocess_timeout = None
    if timeout_s is not None:
        cmd += ["-a", str(timeout_s)]
        subprocess_timeout = max(1.0, float(timeout_s) + 5.0)
    cmd += [rules, file_path]
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=subprocess_timeout,
        )
    except subprocess.TimeoutExpired:
        return False, [], f"timeout>{subprocess_timeout}s"
    except Exception as e:
        return False, [], f"exec_error:{e}"

    if p.returncode not in (0, 1):
        # 0: matched, 1: no matches, others: error
        err = (p.stderr or "").strip() or f"yara_rc={p.returncode}"
        return False, [], err

    matches = _parse_yara_matches(p.stdout or "")
    return bool(matches), matches, None


def main():
    ap = argparse.ArgumentParser(description="Simple YARA evaluation over a file/dir -> CSV")
    ap.add_argument("--rules", required=True, help="YARA rules file path")
    ap.add_argument("--target", default="", help="File or directory to scan (ignored when --scan-list is used).")
    ap.add_argument("--scan-list", default="", help="Scan only files listed in this file (one path per line).")
    ap.add_argument(
        "--base-dir",
        default="",
        help="When using --scan-list, resolve relative paths against this base directory (defaults to --target if provided).",
    )
    ap.add_argument("--out", required=True, help="Output CSV path")
    ap.add_argument("--timeout", type=float, default=30.0, help="Per-file YARA timeout seconds (0 = no timeout).")
    ap.add_argument("--fast", action="store_true", help="Enable YARA fast scan mode (-f).")
    ap.add_argument("--progress-every", type=int, default=500, help="Log progress every N files when --verbose.")
    ap.add_argument("--log", default="", help="Write detailed logs to this file path (e.g. /data/yara_eval.log).")
    ap.add_argument("--verbose", action="store_true", help="Verbose progress + per-match logging.")
    args = ap.parse_args()

    rules = args.rules
    target = Path(args.target) if args.target else None
    out = Path(args.out)
    timeout_s = None if args.timeout <= 0 else float(args.timeout)

    # logging
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if args.log:
        Path(args.log).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(args.log, encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers,
    )
    log = logging.getLogger("yara_eval")

    out.parent.mkdir(parents=True, exist_ok=True)

    scan_list = Path(args.scan_list) if args.scan_list else None
    base_dir = None
    if scan_list is not None:
        if not scan_list.exists():
            raise SystemExit(f"--scan-list not found: {scan_list}")
        if args.base_dir:
            base_dir = Path(args.base_dir)
        elif target is not None:
            base_dir = target
    else:
        if target is None:
            raise SystemExit("Either --target or --scan-list must be provided.")

    scanned = 0
    matched = 0
    started = time.time()
    if args.verbose:
        log.info(
            "START rules=%s target=%s scan_list=%s timeout=%s fast=%s out=%s",
            rules,
            str(target) if target is not None else "",
            str(scan_list) if scan_list is not None else "",
            str(timeout_s) if timeout_s is not None else "none",
            str(args.fast),
            str(out),
        )
    with out.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["path", "matched", "matches", "error"])
        w.writeheader()
        file_iter = iter_from_list(scan_list, base_dir) if scan_list is not None else iter_files(target)  # type: ignore[arg-type]
        for fp in file_iter:
            scanned += 1
            if not fp.exists() or not fp.is_file():
                err = "not_found"
                is_match, matches = False, []
                if args.verbose:
                    log.warning("NOT_FOUND %s", fp)
            else:
                is_match, matches, err = run_yara(rules, str(fp), timeout_s=timeout_s, fast_scan=args.fast)
            if is_match:
                matched += 1
                if args.verbose:
                    log.info("MATCH %s :: %s", ",".join(matches), fp)
            elif err and args.verbose:
                log.warning("ERROR %s :: %s", err, fp)

            if args.verbose and args.progress_every > 0 and (scanned % args.progress_every == 0):
                elapsed = time.time() - started
                rate = scanned / elapsed if elapsed > 0 else 0.0
                log.info("PROGRESS scanned=%d matched=%d rate=%.1f/s last=%s", scanned, matched, rate, fp)

            w.writerow(
                {
                    "path": str(fp),
                    "matched": int(is_match),
                    "matches": ",".join(matches),
                    "error": err or "",
                }
            )

    if args.verbose:
        elapsed = time.time() - started
        rate = scanned / elapsed if elapsed > 0 else 0.0
        log.info("DONE scanned=%d matched=%d rate=%.1f/s", scanned, matched, rate)

    print(f"Scanned: {scanned}")
    print(f"Matched files: {matched} ({(matched / scanned * 100.0) if scanned else 0:.2f}%)")
    print(f"CSV: {out}")
    if args.log:
        print(f"Log: {args.log}")


if __name__ == "__main__":
    main()


