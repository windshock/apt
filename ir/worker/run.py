from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import time
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import re

import requests

from ir.common.models import DumpPolicy, ScanResult, ScopePolicy, WorkOrder, YaraLevel
from ir.common.signing import SignedRequest, sha256_hex


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def load_buckets(path: Path) -> dict[str, set[str]]:
    obj = json.loads(path.read_text(encoding="utf-8"))
    return {
        "high": set(obj.get("high", [])),
        "mid": set(obj.get("mid", [])),
        "low": set(obj.get("low", [])),
    }


def rule_level(rule: str, buckets: dict[str, set[str]]) -> YaraLevel | None:
    if rule in buckets["high"]:
        return YaraLevel.HIGH
    if rule in buckets["mid"]:
        return YaraLevel.MID
    if rule in buckets["low"]:
        return YaraLevel.LOW
    return None


def is_strong_high(rule: str, escalation: dict[str, Any]) -> bool:
    """
    Strong-High gate: exclude generic structural indicators.
    Defaults come from WorkOrder.dump_escalation.
    """
    exclude_prefixes = escalation.get("strong_high_exclude_prefixes") or []
    exclude_rules = set(escalation.get("strong_high_exclude_rules") or [])
    if rule in exclude_rules:
        return False
    for p in exclude_prefixes:
        if rule.startswith(p):
            return False
    return True


def decide_dump_actions(*, hits: list[dict[str, Any]], escalation: dict[str, Any]) -> dict[str, Any]:
    """
    Returns decision about process dump / full dump escalation.
    This MVP only computes decisions; actual dump generation is integrated later.
    """
    high_rules = [h["rule"] for h in hits if h.get("level") == YaraLevel.HIGH.value]
    mid_rules = [h["rule"] for h in hits if h.get("level") == YaraLevel.MID.value]
    low_rules = [h["rule"] for h in hits if h.get("level") == YaraLevel.LOW.value]

    strong_high_rules = [r for r in high_rules if is_strong_high(r, escalation)]

    # base: process dump when any HIGH
    process_dump = len(high_rules) > 0

    # full dump gates
    rc_gate = escalation.get("full_dump_rule_count_gate") or {"high_min": 2, "mid_min": 1}
    high_min = int(rc_gate.get("high_min") or 2)
    mid_min = int(rc_gate.get("mid_min") or 1)
    full_by_count = (len(high_rules) >= high_min) and (len(mid_rules) >= mid_min)

    sh_gate = escalation.get("full_dump_strong_high_gate") or {"enabled": True, "mid_min": 1}
    sh_enabled = bool(sh_gate.get("enabled", True))
    sh_mid_min = int(sh_gate.get("mid_min") or 1)
    full_by_strong = sh_enabled and (len(strong_high_rules) >= 1) and (len(mid_rules) >= sh_mid_min)

    # IMPORTANT: do NOT use HIGH+MID+LOW as an auto-escalation condition.
    full_dump = full_by_count or full_by_strong

    return {
        "process_dump": process_dump,
        "full_dump": full_dump,
        "gates": {
            "high_count": len(high_rules),
            "mid_count": len(mid_rules),
            "low_count": len(low_rules),
            "strong_high_count": len(strong_high_rules),
            "full_by_count_gate": full_by_count,
            "full_by_strong_high_gate": full_by_strong,
        },
        "notes": [
            "Full dump escalation uses (HIGH>=2 & MID>=1) OR (STRONG_HIGH>=1 & MID>=1).",
            "HIGH+MID+LOW is not an auto-escalation condition; Low is profiling only.",
        ],
    }


def run_yara_scan(*, compiled: Path, target: Path) -> list[tuple[str, str]]:
    """
    Returns list of (rule, target_path).
    Uses `yara` CLI output: "<rule> <path>"
    """
    cmd = ["yara", "-C", "-r", "-p", str(os.cpu_count() or 2), str(compiled), str(target)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode not in (0, 1):  # 1 == matches found
        raise RuntimeError(f"yara failed rc={p.returncode}: {p.stderr.strip()}")

    hits: list[tuple[str, str]] = []
    for line in p.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2:
            continue
        hits.append((parts[0], parts[1]))
    return hits


def _try_unmount(mount_dir: Path) -> bool:
    """
    Best-effort unmount for FUSE mount.
    Returns True if an unmount command was executed successfully.
    """
    for cmd in (["fusermount", "-u", str(mount_dir)], ["umount", str(mount_dir)]):
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if p.returncode == 0:
                return True
        except Exception:
            continue
    return False


def _is_fuse_mounted(mount_dir: Path) -> bool:
    try:
        p = subprocess.run(["df", "-T", str(mount_dir)], capture_output=True, text=True, timeout=3)
        return "fuse" in (p.stdout + p.stderr)
    except Exception:
        return False


def _pick_memprocfs_scan_root(mount_dir: Path) -> Path:
    """
    Avoid scanning huge root artifacts like memory.dmp/memory.pmem.
    Prefer structured views (pid/ or forensic/) if present.
    """
    for candidate in (mount_dir / "pid", mount_dir / "forensic", mount_dir / "vm"):
        if candidate.exists() and candidate.is_dir():
            return candidate
    return mount_dir


def _ensure_client_p12(*, out_path: Path, password: str, cert_pem: Path, key_pem: Path) -> None:
    """
    MemProcFS/LeechCore gRPC mTLS interoperability is most reliable with a "legacy" PKCS#12.
    Generate it using openssl when missing.
    """
    if out_path.exists():
        return
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "openssl",
        "pkcs12",
        "-export",
        "-out",
        str(out_path),
        "-inkey",
        str(key_pem),
        "-in",
        str(cert_pem),
        "-passout",
        f"pass:{password}",
        "-legacy",
        "-keypbe",
        "PBE-SHA1-3DES",
        "-certpbe",
        "PBE-SHA1-3DES",
        "-macalg",
        "sha1",
    ]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"openssl pkcs12 export failed rc={p.returncode}: {p.stderr.strip()}")


def run_memprocfs_yara_search(
    *,
    mount_dir: Path,
    rules_file: Path,
    addr_min: int | None = None,
    addr_max: int | None = None,
    timeout_seconds: float = 0.0,
    stall_timeout_seconds: float = 180.0,
    poll_seconds: float = 2.0,
) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    """
    Use MemProcFS built-in FS_YaraSearch interface:
      <mount>/misc/search/yara/yara-rules-file.txt  (write full path to start)
      <mount>/misc/search/yara/status.txt
      <mount>/misc/search/yara/result.txt or result-v.txt
    """
    stats: dict[str, Any] = {"mode": "memprocfs_fs_yara_search", "rules_file": str(rules_file)}
    base = mount_dir / "misc" / "search" / "yara"
    rules_ctl = base / "yara-rules-file.txt"
    status_fp = base / "status.txt"
    result_fp = base / "result.txt"
    result_v_fp = base / "result-v.txt"
    reset_fp = base / "reset.txt"
    addr_min_fp = base / "addr-min.txt"
    addr_max_fp = base / "addr-max.txt"

    if not base.exists():
        raise RuntimeError(f"memprocfs_yara_search_missing:{base}")

    # Optional: override scan range (physical addr space for misc/search/yara).
    # Note: addr-min/max files contain fixed-width hex without 0x prefix.
    if addr_min is not None:
        try:
            addr_min_fp.write_text(f"{int(addr_min):016x}\n", encoding="utf-8")
        except Exception:
            pass
    if addr_max is not None:
        try:
            addr_max_fp.write_text(f"{int(addr_max):016x}\n", encoding="utf-8")
        except Exception:
            pass

    # Record configured scan range (physical for misc/search/yara).
    effective_addr_min = None
    effective_addr_max = None
    span = None
    try:
        if addr_min_fp.exists():
            effective_addr_min = int(addr_min_fp.read_text(errors="replace").strip(), 16)
        if addr_max_fp.exists():
            effective_addr_max = int(addr_max_fp.read_text(errors="replace").strip(), 16)
        if effective_addr_min is not None and effective_addr_max is not None and effective_addr_max >= effective_addr_min:
            span = int(effective_addr_max - effective_addr_min)
    except Exception:
        pass
    stats["addr_min"] = effective_addr_min
    stats["addr_max"] = effective_addr_max
    stats["span_bytes"] = span

    # Cancel any previous search.
    try:
        reset_fp.write_text("1\n", encoding="utf-8")
    except Exception:
        pass

    # Start search by writing full path.
    rules_ctl.write_text(str(rules_file) + "\n", encoding="utf-8")

    deadline = (time.time() + float(timeout_seconds)) if timeout_seconds and timeout_seconds > 0 else None
    last_status = ""
    last_result_size = 0
    started = time.time()
    last_progress_at = time.time()
    last_bytes_read = -1
    last_cur_addr = ""
    last_status_text = ""
    last_speed_mb_s = None

    while True:
        if deadline is not None and time.time() >= deadline:
            stats["timeout"] = True
            break
        try:
            if status_fp.exists():
                last_status = status_fp.read_text(errors="replace")
        except Exception:
            pass

        # Parse progress from status (Bytes read / Current address).
        try:
            cur_addr = ""
            bytes_read = None
            speed_mb_s = None
            for line in last_status.splitlines():
                if line.startswith("Current address:"):
                    cur_addr = line.split(":", 1)[1].strip()
                elif line.startswith("Bytes read:"):
                    v = line.split(":", 1)[1].strip()
                    # values are hex like 0x100000
                    if v.lower().startswith("0x"):
                        bytes_read = int(v, 16)
                elif line.startswith("Speed (MB/s):"):
                    v = line.split(":", 1)[1].strip()
                    try:
                        speed_mb_s = int(v)
                    except Exception:
                        pass
            if bytes_read is not None:
                if bytes_read != last_bytes_read or (cur_addr and cur_addr != last_cur_addr):
                    last_progress_at = time.time()
                    last_bytes_read = bytes_read
                    last_cur_addr = cur_addr
            if speed_mb_s is not None:
                last_speed_mb_s = speed_mb_s
            last_status_text = last_status
        except Exception:
            pass

        try:
            if result_v_fp.exists() and result_v_fp.stat().st_size > 0:
                last_result_size = result_v_fp.stat().st_size
            elif result_fp.exists() and result_fp.stat().st_size > 0:
                last_result_size = result_fp.stat().st_size
        except Exception:
            pass

        # Heuristic completion: status becomes IDLE and result exists, or status indicates done.
        low = last_status.lower()
        if last_result_size > 0 and ("idle" in low or "complete" in low or "finished" in low or "done" in low):
            stats["completed"] = True
            break
        if "completed" in low:
            stats["completed"] = True
            break
        # Some builds may keep Status=RUNNING briefly even after reaching end-of-range.
        # If bytes_read has reached the configured span, treat as completed to avoid false stalls.
        if span is not None and last_bytes_read is not None and last_bytes_read >= max(0, int(span) - 0x1000):
            stats["completed"] = True
            break

        # Stall watchdog (no progress for too long)
        if stall_timeout_seconds and (time.time() - last_progress_at) > float(stall_timeout_seconds):
            stats["stalled"] = True
            break

        time.sleep(float(poll_seconds))

    stats["elapsed_seconds"] = round(time.time() - started, 3)
    stats["status_tail"] = last_status_text[-500:] if last_status_text else last_status[-500:]
    stats["result_size_bytes"] = int(last_result_size)
    stats["last_progress_age_seconds"] = round(time.time() - last_progress_at, 3)
    stats["last_bytes_read"] = None if last_bytes_read < 0 else last_bytes_read
    stats["last_current_address"] = last_cur_addr
    stats["last_speed_mb_s"] = last_speed_mb_s

    # Detect suspicious "early completed" behavior (often indicates rules failed to load
    # or a ruleset compatibility issue). Observed symptom: COMPLETED with only ~1MB read.
    try:
        low = (last_status_text or last_status).lower()
        completed = bool(stats.get("completed")) or ("completed" in low)
        if completed and span and stats.get("last_bytes_read") is not None:
            br = int(stats["last_bytes_read"])
            if br < min(2 * 1024 * 1024, int(span * 0.001)):  # <2MiB or <0.1% of range
                stats["suspicious_early_complete"] = True
    except Exception:
        pass

    if stats.get("timeout") or stats.get("stalled"):
        # best-effort cancel
        try:
            reset_fp.write_text("1\n", encoding="utf-8")
        except Exception:
            pass
        return [], stats

    # Prefer verbose result when available.
    out_text = ""
    try:
        if result_v_fp.exists() and result_v_fp.stat().st_size > 0:
            out_text = result_v_fp.read_text(errors="replace")
            stats["result_file"] = str(result_v_fp)
        else:
            out_text = result_fp.read_text(errors="replace")
            stats["result_file"] = str(result_fp)
    except Exception as e:
        raise RuntimeError(f"memprocfs_yara_read_failed:{type(e).__name__}")

    hits: list[tuple[str, str]] = []
    for line in out_text.splitlines():
        line = line.strip()
        if not line:
            continue
        # Expect rule name first token; keep the whole line as "target".
        parts = line.split(maxsplit=1)
        rule = parts[0]
        hits.append((rule, line))

    stats["raw_hit_count"] = len(hits)
    return hits, stats


def _read_physmemmap_ranges(*, mount_dir: Path) -> tuple[list[tuple[int, int]], dict[str, Any]]:
    """
    Read MemProcFS physical memory map (ranges with actual backing pages).

    Why: addr-max reflects the *top of physical address space*, which may include large holes.
    Scanning only the physmemmap ranges reduces wasted reads and gives realistic ETA.
    """
    stats: dict[str, Any] = {"source": "sys/memory/physmemmap.txt"}
    fp = mount_dir / "sys" / "memory" / "physmemmap.txt"
    ranges: list[tuple[int, int]] = []
    try:
        txt = fp.read_text(errors="replace")
    except Exception as e:
        stats["error"] = f"{type(e).__name__}: {e}"
        return [], stats

    total = 0
    for line in txt.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Format: "<idx> <base> - <top>"
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            base = int(parts[1], 16)
            top = int(parts[3], 16)
        except Exception:
            continue
        if top < base:
            continue
        ranges.append((base, top))
        total += (top - base + 1)
    stats["range_count"] = len(ranges)
    stats["total_bytes"] = total
    stats["total_gib"] = round(total / 1024 / 1024 / 1024, 6) if total else 0.0
    return ranges, stats


def run_memprocfs_yara_search_over_ranges(
    *,
    mount_dir: Path,
    rules_file: Path,
    ranges: list[tuple[int, int]],
    timeout_seconds: float = 0.0,
    stall_timeout_seconds: float = 180.0,
) -> tuple[list[tuple[str, str]], dict[str, Any]]:
    """
    Run FS_YaraSearch multiple times, each constrained to a physmemmap-backed range.
    Aggregate results and per-range stats.
    """
    agg_hits: list[tuple[str, str]] = []
    agg_stats: dict[str, Any] = {
        "mode": "memprocfs_fs_yara_search_ranges",
        "rules_file": str(rules_file),
        "range_count": len(ranges),
        "ranges": [],
        "total_span_bytes": 0,
    }

    total_span = 0
    for idx, (base, top) in enumerate(ranges):
        span = int(top - base + 1)
        total_span += span

        hits, st = run_memprocfs_yara_search(
            mount_dir=mount_dir,
            rules_file=rules_file,
            addr_min=base,
            addr_max=top,
            timeout_seconds=timeout_seconds,
            stall_timeout_seconds=stall_timeout_seconds,
        )
        agg_hits.extend(hits)
        agg_stats["ranges"].append(
            {
                "index": idx,
                "base": base,
                "top": top,
                "span_bytes": span,
                "yara_search": st,
            }
        )

        # If the underlying search is stalling, stop early (caller can decide to retry).
        if st.get("timeout") or st.get("stalled"):
            agg_stats["aborted"] = True
            agg_stats["aborted_at_range_index"] = idx
            break

    agg_stats["total_span_bytes"] = total_span
    agg_stats["total_span_gib"] = round(total_span / 1024 / 1024 / 1024, 6) if total_span else 0.0
    agg_stats["raw_hit_count"] = len(agg_hits)
    return agg_hits, agg_stats


def ensure_high_mid_rules_index(
    *,
    buckets_path: Path,
    rules_dir: Path,
    out_dir: Path,
) -> Path:
    """
    Build an include-index YARA ruleset (source .yar) containing only HIGH/MID bucket rules.

    Why index (source) and not compiled?
    - MemProcFS FS_YaraSearch loads rules via vmmyara.* which may reject/short-circuit on
      compiled artifacts produced by a different yarac/libyara version.
    - A source include-index is the most compatible option for FS_YaraSearch.

    We still use `yarac` as a *validator* to auto-exclude problematic upstream rule files.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    index_fp = out_dir / "high_mid_index.yar"
    # Optional validation output (not used by FS_YaraSearch).
    compiled_fp = out_dir / "high_mid.compiled"
    stamp_fp = out_dir / "high_mid_index.stamp.json"

    obj = json.loads(buckets_path.read_text(encoding="utf-8"))
    wanted = set(obj.get("high", [])) | set(obj.get("mid", []))

    # Cache: reuse if stamp matches. (rules_dir mtime is a coarse proxy; good enough for MVP)
    try:
        if index_fp.exists() and stamp_fp.exists():
            stamp = json.loads(stamp_fp.read_text(encoding="utf-8"))
            if (
                stamp.get("wanted_count") == len(wanted)
                and stamp.get("rules_dir") == str(rules_dir)
                and stamp.get("rules_dir_mtime") == rules_dir.stat().st_mtime
            ):
                return index_fp
    except Exception:
        pass

    rule_decl = re.compile(r"^[ \t]*rule[ \t]+([A-Za-z0-9_]+)", re.MULTILINE)
    include_files: list[Path] = []

    for fp in sorted(rules_dir.glob("*.yar")):
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        names = set(rule_decl.findall(text))
        if names & wanted:
            include_files.append(fp)

    if not include_files:
        raise RuntimeError(f"no_high_mid_rule_files_found under {rules_dir}")

    excluded: list[str] = []
    for _ in range(15):
        index_fp.write_text("".join([f'include "{str(p)}"\n' for p in include_files]), encoding="utf-8")

        # Validate with yarac (best-effort). If yarac is missing, accept index as-is.
        try:
            p = subprocess.run(["yarac", str(index_fp), str(compiled_fp)], capture_output=True, text=True)
        except FileNotFoundError:
            break

        if p.returncode == 0:
            break

        # Extract offending files from error lines and drop them, then retry.
        stderr = p.stderr or ""
        offenders: set[str] = set()
        for line in stderr.splitlines():
            if not line.startswith("error:"):
                continue
            # Example: "error: rule ... in /path/file.yar(44): ..."
            pos = line.find(" in ")
            if pos == -1:
                continue
            rest = line[pos + 4 :]
            cut = rest.find(".yar(")
            if cut == -1:
                continue
            offenders.add(rest[: cut + 4])
        if not offenders:
            raise RuntimeError(f"yarac validation failed rc={p.returncode}: {stderr.strip()}")

        new_include_files: list[Path] = []
        for fp in include_files:
            if str(fp) in offenders:
                excluded.append(str(fp))
            else:
                new_include_files.append(fp)
        include_files = new_include_files
        if not include_files:
            raise RuntimeError(f"yarac failed: all rule files excluded. last_error={stderr.strip()}")
    else:
        raise RuntimeError("yarac failed: too many retries excluding bad rules")

    stamp_fp.write_text(
        json.dumps(
            {
                "wanted_count": len(wanted),
                "included_files": len(include_files),
                "excluded_files": excluded,
                "rules_dir": str(rules_dir),
                "rules_dir_mtime": rules_dir.stat().st_mtime,
                "built_at": utc_now().isoformat(),
                "note": "FS_YaraSearch uses source include-index for vmmyara compatibility.",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return index_fp


def ensure_high_mid_rules_merged(
    *,
    buckets_path: Path,
    rules_dir: Path,
    out_dir: Path,
) -> Path:
    """
    Build a HIGH+MID-only **single source rules file** compatible with MemProcFS FS_YaraSearch.

    Important:
    - MemProcFS (vmmyara) does not reliably honor YARA `include` in some builds/environments.
      Symptom: FS_YaraSearch immediately completes with Bytes read = 0.
    - To avoid that, we merge the selected `.yar` files into one `.yar` and pass that path.

    We still use an include-index + `yarac` compile as a *validator* to auto-exclude problematic
    upstream rule files (so errors still point to the original `.yar` files).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    index_fp = out_dir / "high_mid_index.yar"
    merged_fp = out_dir / "high_mid_merged.yar"
    compiled_fp = out_dir / "high_mid_merged.compiled"
    stamp_fp = out_dir / "high_mid_merged.stamp.json"

    obj = json.loads(buckets_path.read_text(encoding="utf-8"))
    wanted = set(obj.get("high", [])) | set(obj.get("mid", []))

    # Cache reuse (bump format_version when output format changes)
    try:
        if merged_fp.exists() and stamp_fp.exists():
            stamp = json.loads(stamp_fp.read_text(encoding="utf-8"))
            if (
                stamp.get("format_version") == 3
                and stamp.get("wanted_count") == len(wanted)
                and stamp.get("rules_dir") == str(rules_dir)
                and stamp.get("rules_dir_mtime") == rules_dir.stat().st_mtime
            ):
                return merged_fp
    except Exception:
        pass

    rule_decl = re.compile(r"^[ \t]*rule[ \t]+([A-Za-z0-9_]+)", re.MULTILINE)
    import_mod_decl = re.compile(r'^[ \t]*import[ \t]+(\"([^\"]+)\"|\'([^\']+)\')[ \t]*$', re.MULTILINE)

    # vmmyara (MemProcFS) supports only a subset of YARA modules.
    # We empirically observed `magic` causing immediate COMPLETED/0 bytes behavior.
    supported_modules = {"pe", "math", "elf", "dotnet", "console"}
    include_files: list[Path] = []
    excluded_by_module: list[str] = []

    for fp in sorted(rules_dir.glob("*.yar")):
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        mods: set[str] = set()
        for m in import_mod_decl.findall(text):
            # m is tuple: (full quoted, double, single)
            mod = m[1] or m[2]
            if mod:
                mods.add(mod)
        if any(mod not in supported_modules for mod in mods):
            excluded_by_module.append(str(fp))
            continue
        names = set(rule_decl.findall(text))
        if names & wanted:
            include_files.append(fp)

    if not include_files:
        raise RuntimeError(f"no_high_mid_rule_files_found under {rules_dir}")

    excluded: list[str] = []

    # Validate & auto-exclude using yarac + include-index (so stderr includes original file names).
    for _ in range(15):
        index_fp.write_text("".join([f'include "{str(p)}"\n' for p in include_files]), encoding="utf-8")
        try:
            p = subprocess.run(["yarac", str(index_fp), str(compiled_fp)], capture_output=True, text=True)
        except FileNotFoundError:
            # If yarac isn't available, skip validation and just merge.
            break
        if p.returncode == 0:
            break

        stderr = p.stderr or ""
        offenders: set[str] = set()
        for line in stderr.splitlines():
            if not line.startswith("error:"):
                continue
            pos = line.find(" in ")
            if pos == -1:
                continue
            rest = line[pos + 4 :]
            cut = rest.find(".yar(")
            if cut == -1:
                continue
            offenders.add(rest[: cut + 4])
        if not offenders:
            raise RuntimeError(f"yarac validation failed rc={p.returncode}: {stderr.strip()}")

        new_include_files: list[Path] = []
        for fp in include_files:
            if str(fp) in offenders:
                excluded.append(str(fp))
            else:
                new_include_files.append(fp)
        include_files = new_include_files
        if not include_files:
            raise RuntimeError(f"yarac failed: all rule files excluded. last_error={stderr.strip()}")
    else:
        raise RuntimeError("yarac failed: too many retries excluding bad rules")

    # Merge into one YARA source file (dedupe imports to avoid noise).
    # Match lines like: import "pe"  OR  import 'math'
    import_re = re.compile(r"^[ \t]*import[ \t]+(\"[^\"]+\"|'[^']+')[ \t]*$", re.MULTILINE)
    imports: set[str] = set()
    bodies: list[str] = []
    for fp in include_files:
        try:
            txt = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in import_re.findall(txt):
            # Keep only supported modules at top; files requiring unsupported modules were excluded above.
            mod = m.strip().strip('"').strip("'")
            if mod in supported_modules:
                imports.add(f"import {m}")
        # Remove import lines (we re-add at top)
        txt_wo_imports = import_re.sub("", txt)
        bodies.append(f"// ---- {fp.name} ----\n{txt_wo_imports.strip()}\n")

    merged = ""
    if imports:
        merged += "\n".join(sorted(imports)) + "\n\n"
    merged += "\n".join(bodies).strip() + "\n"
    merged_fp.write_text(merged, encoding="utf-8")

    stamp_fp.write_text(
        json.dumps(
            {
                "format_version": 3,
                "wanted_count": len(wanted),
                "included_files": len(include_files),
                "excluded_files": excluded,
                "excluded_by_module": excluded_by_module,
                "supported_modules": sorted(supported_modules),
                "rules_dir": str(rules_dir),
                "rules_dir_mtime": rules_dir.stat().st_mtime,
                "built_at": utc_now().isoformat(),
                "note": "FS_YaraSearch uses merged source file (include is unreliable in vmmyara).",
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return merged_fp


def ensure_high_mid_compiled_ruleset(
    *,
    buckets_path: Path,
    rules_dir: Path,
    out_dir: Path,
) -> Path:
    """
    Build a smaller YARA compiled ruleset containing only files that define
    HIGH/MID bucket rules. This speeds up MemProcFS YaraSearch substantially.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    index_fp = out_dir / "high_mid_index.yar"
    compiled_fp = out_dir / "high_mid.compiled"
    stamp_fp = out_dir / "high_mid.stamp.json"

    obj = json.loads(buckets_path.read_text(encoding="utf-8"))
    wanted = set(obj.get("high", [])) | set(obj.get("mid", []))

    # If already built for same bucket size and rules_dir mtime, reuse.
    try:
        if compiled_fp.exists() and stamp_fp.exists():
            stamp = json.loads(stamp_fp.read_text(encoding="utf-8"))
            if (
                stamp.get("wanted_count") == len(wanted)
                and stamp.get("rules_dir") == str(rules_dir)
                and stamp.get("rules_dir_mtime") == rules_dir.stat().st_mtime
            ):
                return compiled_fp
    except Exception:
        pass

    rule_decl = re.compile(r"^[ \t]*rule[ \t]+([A-Za-z0-9_]+)", re.MULTILINE)
    include_files: list[Path] = []

    for fp in sorted(rules_dir.glob("*.yar")):
        try:
            text = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        names = set(rule_decl.findall(text))
        if names & wanted:
            include_files.append(fp)

    if not include_files:
        raise RuntimeError(f"no_high_mid_rule_files_found under {rules_dir}")

    excluded: list[str] = []
    # Compile with auto-exclusion of problematic rule files (some upstream rules
    # may not compile cleanly, e.g. unreferenced strings).
    for _ in range(15):
        # Build index (use absolute paths to avoid include base issues).
        index_fp.write_text(
            "".join([f'include "{str(p)}"\n' for p in include_files]),
            encoding="utf-8",
        )

        cmd = ["yarac", str(index_fp), str(compiled_fp)]
        p = subprocess.run(cmd, capture_output=True, text=True)
        if p.returncode == 0:
            break

        # Extract offending files from error lines and drop them, then retry.
        stderr = p.stderr or ""
        offenders: set[str] = set()
        for line in stderr.splitlines():
            if not line.startswith("error:"):
                continue
            # Example: "error: rule ... in /path/file.yar(44): ..."
            pos = line.find(" in ")
            if pos == -1:
                continue
            rest = line[pos + 4 :]
            cut = rest.find(".yar(")
            if cut == -1:
                continue
            offenders.add(rest[: cut + 4])
        if not offenders:
            raise RuntimeError(f"yarac failed rc={p.returncode}: {stderr.strip()}")

        new_include_files: list[Path] = []
        for fp in include_files:
            if str(fp) in offenders:
                excluded.append(str(fp))
            else:
                new_include_files.append(fp)
        include_files = new_include_files
        if not include_files:
            raise RuntimeError(f"yarac failed: all rule files excluded. last_error={stderr.strip()}")
    else:
        raise RuntimeError("yarac failed: too many retries excluding bad rules")

    stamp_fp.write_text(
        json.dumps(
            {
                "wanted_count": len(wanted),
                "included_files": len(include_files),
                "excluded_files": excluded,
                "rules_dir": str(rules_dir),
                "rules_dir_mtime": rules_dir.stat().st_mtime,
                "built_at": utc_now().isoformat(),
            },
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    return compiled_fp

def maybe_run_memprocfs(wo: WorkOrder, stats: dict[str, Any]) -> tuple[Path, subprocess.Popen[str]] | None:
    """
    If enabled and binary exists, try to run MemProcFS to mount a memory view.
    This is a best-effort MVP wrapper: it prepares the execution surface but does not
    guarantee success without real LeechAgent + Windows endpoint.
    """
    cfg = wo.memprocfs or {}
    if not cfg.get("enabled", False):
        stats["memprocfs"] = {"enabled": False}
        return None

    bin_path = Path(cfg.get("binary") or "")
    lib_dir = Path(cfg.get("lib_dir") or "")
    mount_dir = Path(cfg.get("mount_dir") or "/tmp/memprocfs")
    extra_args = cfg.get("extra_args") or []

    la = wo.leechagent or {}
    mode = la.get("mode", "grpc")
    host = la.get("host")
    port = int(la.get("port") or 28474)
    if not host:
        stats["memprocfs"] = {"enabled": True, "skipped": True, "reason": "leechagent.host missing"}
        return None

    if not bin_path.exists():
        stats["memprocfs"] = {"enabled": True, "skipped": True, "reason": f"binary_missing:{bin_path}"}
        return None

    if lib_dir and not lib_dir.exists():
        stats["memprocfs_lib_dir_missing"] = str(lib_dir)

    mount_dir.mkdir(parents=True, exist_ok=True)

    # Build default args automatically unless explicitly overridden.
    if bool(cfg.get("auto_build_args", True)) and not extra_args:
        device = str(cfg.get("device") or "pmem")
        forensic = bool(cfg.get("forensic", True))
        verbose = bool(cfg.get("verbose", True))
        server_ca_cert = str(cfg.get("server_ca_cert") or "/data/ir/pki/ca.crt.pem")

        # client p12 (MemProcFS client cert for LeechAgent mTLS)
        client_p12_password = str(cfg.get("client_p12_password") or "changeit")
        client_p12_path = cfg.get("client_p12_path")
        if client_p12_path:
            client_p12 = Path(client_p12_path)
        else:
            # Default: derive from worker API mTLS cert/key paths (they exist in compose).
            cert_pem = Path(os.getenv("IR_TLS_CERT", "/data/ir/mtls/host-01/client.crt.pem"))
            key_pem = Path(os.getenv("IR_TLS_KEY", "/data/ir/mtls/host-01/client.key.pem"))
            client_p12 = cert_pem.with_name("client_legacy.p12")
            if cert_pem.exists() and key_pem.exists():
                _ensure_client_p12(out_path=client_p12, password=client_p12_password, cert_pem=cert_pem, key_pem=key_pem)

        server_name = la.get("server_name") or "leechagent"
        remote = (
            f"grpc://{server_name}:{host}:"
            f"server-cert={server_ca_cert},"
            f"client-cert-p12={str(client_p12)},"
            f"client-cert-p12-password={client_p12_password}"
        )

        extra_args = ["-device", device, "-remote", remote]
        if forensic:
            extra_args += ["-forensic", "1"]
        if verbose:
            extra_args += ["-v"]

    # MemProcFS uses -mount for mount point on Linux.
    cmd = [str(bin_path), "-mount", str(mount_dir)] + list(extra_args)
    stats["memprocfs"] = {"enabled": True, "cmd": cmd, "leechagent": {"mode": mode, "host": host, "port": port}}

    # Start in background and wait for mount to populate.
    # IMPORTANT: The mount is only visible inside this container/namespace,
    # so scan must happen in the same process/container.
    try:
        env = os.environ.copy()
        # MemProcFS ships core shared libs (e.g., vmm.so) alongside the binary,
        # plus optional libs in lib_dir (e.g., libleechgrpc.so).
        ld_parts: list[str] = []
        if bin_path.parent.exists():
            ld_parts.append(str(bin_path.parent))
        if lib_dir and lib_dir.exists():
            ld_parts.append(str(lib_dir))
        if env.get("LD_LIBRARY_PATH"):
            ld_parts.append(env["LD_LIBRARY_PATH"])
        env["LD_LIBRARY_PATH"] = ":".join([p for p in ld_parts if p]).rstrip(":")
        # Some environments (notably ARM64) show intermittent SIGBUS/SIGSEGV during init.
        # We'll retry a few times before falling back to the configured scan target.
        max_attempts = int(cfg.get("max_attempts") or 4)
        attempt_timeout = float(cfg.get("attempt_timeout_seconds") or 120)
        stats["memprocfs"]["attempts"] = []

        for attempt in range(1, max_attempts + 1):
            # cleanup any stale mount contents
            try:
                _try_unmount(mount_dir)
            except Exception:
                pass
            try:
                for child in mount_dir.iterdir():
                    # avoid raising on fuse entries
                    try:
                        if child.is_file() or child.is_symlink():
                            child.unlink(missing_ok=True)
                        elif child.is_dir():
                            # best-effort; may fail on special entries
                            subprocess.run(["rm", "-rf", str(child)], capture_output=True, text=True, timeout=5)
                    except Exception:
                        continue
            except Exception:
                pass

            p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True, env=env)
            att: dict[str, Any] = {"attempt": attempt, "pid": p.pid, "started_at": utc_now().isoformat()}
            stats["memprocfs"]["pid"] = p.pid

            deadline = time.time() + attempt_timeout
            while time.time() < deadline:
                if p.poll() is not None:
                    att["returncode"] = p.returncode
                    break

                try:
                    if mount_dir.exists() and _is_fuse_mounted(mount_dir) and any(mount_dir.iterdir()):
                        scan_root = _pick_memprocfs_scan_root(mount_dir)
                        att["mounted"] = True
                        att["scan_root"] = str(scan_root)
                        stats["memprocfs"]["attempts"].append(att)
                        stats["memprocfs"]["mounted"] = True
                        stats["memprocfs"]["mount_dir"] = str(mount_dir)
                        stats["memprocfs"]["scan_root"] = str(scan_root)
                        return mount_dir, p
                except Exception:
                    pass
                time.sleep(0.5)

            if p.poll() is None:
                att["timeout"] = True
            stats["memprocfs"]["attempts"].append(att)
            try:
                p.terminate()
                p.wait(timeout=10)
            except Exception:
                pass
            try:
                _try_unmount(mount_dir)
            except Exception:
                pass
            time.sleep(1.0)

        stats["memprocfs"]["failed_after_attempts"] = max_attempts
        return None
    except Exception as e:
        stats["memprocfs"]["error"] = f"{type(e).__name__}: {e}"
        return None


def _headers(key: str, method: str, path: str, body: bytes, require_sig: bool) -> dict[str, str]:
    h = {"X-IR-Key": key, "Content-Type": "application/json"}
    if require_sig:
        s = SignedRequest.sign(key=key, method=method, path=path, body=body)
        h["X-IR-Timestamp"] = str(s.timestamp)
        h["X-IR-Signature"] = s.signature
    return h


def post_json(*, orch_url: str, key: str, require_sig: bool, path: str, payload: dict[str, Any]) -> requests.Response:
    url = orch_url.rstrip("/") + path
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = _headers(key, "POST", path, body, require_sig)
    verify = os.getenv("IR_TLS_CA")
    cert = None
    cert_file = os.getenv("IR_TLS_CERT")
    key_file = os.getenv("IR_TLS_KEY")
    if cert_file and key_file:
        cert = (cert_file, key_file)
    return requests.post(url, data=body, headers=headers, timeout=30, verify=verify or True, cert=cert)


def get_json(*, orch_url: str, key: str, require_sig: bool, path: str) -> requests.Response:
    url = orch_url.rstrip("/") + path
    body = b""
    headers = _headers(key, "GET", path, body, require_sig)
    verify = os.getenv("IR_TLS_CA")
    cert = None
    cert_file = os.getenv("IR_TLS_CERT")
    key_file = os.getenv("IR_TLS_KEY")
    if cert_file and key_file:
        cert = (cert_file, key_file)
    return requests.get(url, headers=headers, timeout=30, verify=verify or True, cert=cert)


def post_file(*, orch_url: str, key: str, require_sig: bool, path: str, file_path: Path) -> requests.Response:
    url = orch_url.rstrip("/") + path
    # For multipart, we keep signature optional; if enabled we sign empty body and rely on mTLS in production.
    headers = {"X-IR-Key": key}
    if require_sig:
        s = SignedRequest.sign(key=key, method="POST", path=path, body=b"")
        headers["X-IR-Timestamp"] = str(s.timestamp)
        headers["X-IR-Signature"] = s.signature
    with file_path.open("rb") as f:
        files = {"file": (file_path.name, f)}
        verify = os.getenv("IR_TLS_CA")
        cert = None
        cert_file = os.getenv("IR_TLS_CERT")
        key_file = os.getenv("IR_TLS_KEY")
        if cert_file and key_file:
            cert = (cert_file, key_file)
        return requests.post(url, files=files, headers=headers, timeout=300, verify=verify or True, cert=cert)


def sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="IR Worker (MVP): run yara scan and upload results/evidence.")
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--agent-id", default=None)
    ap.add_argument("--orch-url", default=os.getenv("IR_ORCH_URL", "http://ir-orchestrator:8080"))
    ap.add_argument("--shared-key", default=os.getenv("IR_SHARED_KEY", "dev"))
    ap.add_argument("--require-signature", action="store_true", default=os.getenv("IR_REQUIRE_SIGNATURE", "0") == "1")
    ap.add_argument("--buckets", default=os.getenv("IR_YARAHUB_BUCKETS", "/data/ir/yarahub_buckets.json"))
    ap.add_argument("--compiled", default=os.getenv("IR_YARAHUB_COMPILED", "/data/yaraify/yarahub.compiled"))
    ap.add_argument("--scan-target", default=os.getenv("IR_SCAN_TARGET", "/data/mdmp_extracted"))
    ap.add_argument("--dump-dir", default=os.getenv("IR_DUMP_DIR", "/data/ir/dumps_inbox"))
    args = ap.parse_args()

    case_id = args.case_id
    orch_url = args.orch_url
    key = args.shared_key
    require_sig = bool(args.require_signature)

    # WorkOrder: issued by orchestrator (default: High/Mid only).
    r_wo = get_json(orch_url=orch_url, key=key, require_sig=require_sig, path=f"/v1/cases/{case_id}/work-order")
    if r_wo.status_code >= 300:
        print(r_wo.text, file=sys.stderr)
        return 2
    wo = WorkOrder.model_validate(r_wo.json())

    started = utc_now()
    hits_out: list[dict[str, Any]] = []
    stats: dict[str, Any] = {}

    buckets_path = Path(args.buckets)
    compiled_path = Path(args.compiled)
    target_path = Path(args.scan_target)

    if wo.yara_ruleset:
        compiled_path = Path(wo.yara_ruleset)

    if buckets_path.exists():
        buckets = load_buckets(buckets_path)
    else:
        buckets = {"high": set(), "mid": set(), "low": set()}
        stats["buckets_missing"] = str(buckets_path)

    # If MemProcFS is enabled and successfully mounted, prefer scanning mounted view.
    memprocfs_ctx = maybe_run_memprocfs(wo, stats)
    memprocfs_proc: subprocess.Popen[str] | None = None
    keepalive_stop: threading.Event | None = None
    keepalive_thread: threading.Thread | None = None
    memprocfs_mount: Path | None = None
    if memprocfs_ctx:
        memprocfs_mount, memprocfs_proc = memprocfs_ctx
        # default scan_root for fallback filesystem scan
        target_path = _pick_memprocfs_scan_root(memprocfs_mount)

        # LeechAgent has a server-side client keepalive timeout (e.g. 75s in upstream).
        # To avoid idle disconnects during long processing, periodically touch the mount.
        keepalive_stop = threading.Event()
        keepalive_interval_s = float((wo.memprocfs or {}).get("keepalive_interval_seconds") or 20)
        keepalive_stats: dict[str, Any] = {
            "enabled": True,
            "interval_seconds": keepalive_interval_s,
            "ticks": 0,
            "successes": 0,
            "failures": 0,
            "last_success_at": None,
            "last_error": None,
            "method": "read_status_or_iterdir",
            "note": "Best-effort keepalive; LeechAgent has ~75s inactivity timeout upstream.",
        }

        def _keepalive_loop() -> None:
            while not keepalive_stop.is_set():
                keepalive_stats["ticks"] += 1
                try:
                    status_fp = memprocfs_mount / "misc" / "search" / "yara" / "status.txt"
                    if status_fp.exists():
                        _ = status_fp.read_text(errors="replace")[:256]
                    else:
                        _ = next(iter(target_path.iterdir()), None)
                    keepalive_stats["successes"] += 1
                    keepalive_stats["last_success_at"] = utc_now().isoformat()
                except Exception as e:
                    keepalive_stats["failures"] += 1
                    keepalive_stats["last_error"] = f"{type(e).__name__}: {e}"
                keepalive_stop.wait(keepalive_interval_s)

        keepalive_thread = threading.Thread(target=_keepalive_loop, name="memprocfs-keepalive", daemon=True)
        keepalive_thread.start()
        stats.setdefault("memprocfs", {})["keepalive"] = keepalive_stats

    try:
        raw_hits: list[tuple[str, str]] = []

        if memprocfs_mount is not None:
            # MemProcFS path: do NOT require a compiled ruleset. We feed a merged source .yar
            # to vmmyara FS_YaraSearch for max compatibility.
            rules_for_mem = None
            try:
                rules_for_mem = ensure_high_mid_rules_merged(
                    buckets_path=buckets_path,
                    rules_dir=Path("/data/yaraify/rules"),
                    out_dir=Path("/data/yaraify/out"),
                )
                stats.setdefault("memprocfs", {}).setdefault("ruleset", {"mode": "high_mid_merged", "path": str(rules_for_mem)})
            except Exception as e:
                stats.setdefault("memprocfs", {}).setdefault("ruleset_error", f"{type(e).__name__}: {e}")

            if not rules_for_mem or not Path(rules_for_mem).exists():
                stats.update({"scan_skipped": True, "reason": "memprocfs_rules_missing", "rules_dir": "/data/yaraify/rules"})
            else:
                phys_ranges, phys_stats = _read_physmemmap_ranges(mount_dir=memprocfs_mount)
                stats.setdefault("memprocfs", {}).setdefault("physmemmap", phys_stats)
                if phys_ranges:
                    raw_hits, mp_yara_stats = run_memprocfs_yara_search_over_ranges(
                        mount_dir=memprocfs_mount,
                        rules_file=Path(rules_for_mem),
                        ranges=phys_ranges,
                        timeout_seconds=float((wo.memprocfs or {}).get("yara_timeout_seconds") or 0),
                        stall_timeout_seconds=float((wo.memprocfs or {}).get("yara_stall_timeout_seconds") or 180),
                    )
                else:
                    raw_hits, mp_yara_stats = run_memprocfs_yara_search(
                        mount_dir=memprocfs_mount,
                        rules_file=Path(rules_for_mem),
                        timeout_seconds=float((wo.memprocfs or {}).get("yara_timeout_seconds") or 0),
                        stall_timeout_seconds=float((wo.memprocfs or {}).get("yara_stall_timeout_seconds") or 180),
                    )
                stats.setdefault("memprocfs", {}).setdefault("yara_search", mp_yara_stats)
                stats["scan_target"] = str(memprocfs_mount)
        else:
            # Fallback filesystem scan: requires a compiled ruleset + scan target directory.
            if compiled_path.exists() and target_path.exists():
                raw_hits = run_yara_scan(compiled=compiled_path, target=target_path)
                stats["scan_target"] = str(target_path)
                stats["yara_compiled"] = str(compiled_path)
            else:
                stats.update(
                    {
                        "scan_skipped": True,
                        "yara_compiled_exists": compiled_path.exists(),
                        "scan_target_exists": target_path.exists(),
                    }
                )

        kept = 0
        for rule, tgt in raw_hits:
            lvl = rule_level(rule, buckets)
            if lvl and lvl in wo.yara_levels:
                kept += 1
                hits_out.append({"rule": rule, "level": lvl.value, "target": tgt, "meta": {}})
        if raw_hits:
            stats["raw_hit_count"] = len(raw_hits)
            stats["kept_hit_count"] = kept
    finally:
        if keepalive_stop is not None:
            keepalive_stop.set()
        if keepalive_thread is not None:
            try:
                keepalive_thread.join(timeout=2)
            except Exception:
                pass
        if memprocfs_proc is not None:
            shutdown: dict[str, Any] = {"attempts": []}
            try:
                # Try graceful shutdown first. If we hard-kill, LeechAgent may later log
                # "timeout after 75s" while cleaning up an abandoned client.
                sigint_wait = int((wo.memprocfs or {}).get("shutdown_sigint_wait_seconds") or 60)
                sigterm_wait = int((wo.memprocfs or {}).get("shutdown_sigterm_wait_seconds") or 30)

                shutdown["attempts"].append({"signal": "SIGINT", "wait_seconds": sigint_wait})
                memprocfs_proc.send_signal(signal.SIGINT)
                memprocfs_proc.wait(timeout=sigint_wait)
            except Exception as e:
                shutdown["attempts"].append(
                    {"signal": "SIGTERM", "wait_seconds": sigterm_wait, "error": f"{type(e).__name__}: {e}"}
                )
                try:
                    memprocfs_proc.terminate()
                    memprocfs_proc.wait(timeout=sigterm_wait)
                except Exception as e2:
                    shutdown["attempts"].append({"signal": "SIGKILL", "error": f"{type(e2).__name__}: {e2}"})
                    try:
                        memprocfs_proc.kill()
                    except Exception:
                        pass
            shutdown["returncode"] = memprocfs_proc.returncode
            stats.setdefault("memprocfs", {})["shutdown"] = shutdown
            mount_dir = Path((wo.memprocfs or {}).get("mount_dir") or "/tmp/memprocfs")
            # Prefer unmount before signals: a clean FUSE shutdown can allow MemProcFS
            # to close remote handles and avoid LeechAgent "timeout after 75s" cleanup logs.
            um_ok = _try_unmount(mount_dir)
            shutdown["attempts"].insert(0, {"action": "fusermount_u", "success": um_ok})

            # Give MemProcFS a moment to exit on its own after unmount.
            try:
                memprocfs_proc.wait(timeout=10)
            except Exception:
                pass

    finished = utc_now()

    planned = decide_dump_actions(hits=hits_out, escalation=wo.dump_escalation)

    result = ScanResult(
        case_id=case_id,
        agent_id=args.agent_id,
        started_at=started,
        finished_at=finished,
        scope_policy=wo.scope_policy,
        yara_levels=wo.yara_levels,
        dump_policy=wo.dump_policy,
        hits=[],
        planned_actions=planned,
        stats=stats,
    ).model_dump(mode="json")

    # attach hits (as plain dicts)
    result["hits"] = hits_out

    r = post_json(orch_url=orch_url, key=key, require_sig=require_sig, path=f"/v1/cases/{case_id}/results", payload=result)
    if r.status_code >= 300:
        print(r.text, file=sys.stderr)
        return 3

    # Optional: upload dump artifacts if present (pre-wired for Windows PoC).
    dump_dir = Path(args.dump_dir) / case_id
    uploaded_files: list[dict[str, Any]] = []
    if dump_dir.exists():
        for fp in sorted(dump_dir.glob("*")):
            if not fp.is_file():
                continue
            rr = post_file(orch_url=orch_url, key=key, require_sig=require_sig, path=f"/v1/cases/{case_id}/evidence", file_path=fp)
            if rr.status_code < 300:
                uploaded_files.append({"name": fp.name, "sha256": sha256_file(fp), "size": fp.stat().st_size})
            else:
                stats.setdefault("evidence_upload_errors", []).append({"file": fp.name, "status": rr.status_code})

    # manifest
    manifest = {
        "case_id": case_id,
        "endpoint_id": args.agent_id,
        "created_at": utc_now().isoformat(),
        "files": [
            {
                "name": "result.json",
                "sha256": sha256_hex(json.dumps(result, ensure_ascii=False).encode("utf-8")),
                "size": len(json.dumps(result, ensure_ascii=False).encode("utf-8")),
            }
        ]
        + uploaded_files,
    }
    r2 = post_json(orch_url=orch_url, key=key, require_sig=require_sig, path=f"/v1/cases/{case_id}/manifest", payload=manifest)
    if r2.status_code >= 300:
        print(r2.text, file=sys.stderr)
        return 4

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

