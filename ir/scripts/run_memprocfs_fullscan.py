from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Run MemProcFS FS_YaraSearch over physmem-backed ranges (remote pmem via LeechAgent)."
    )
    ap.add_argument("--win-ip", required=True, help="Windows endpoint IP running LeechAgent gRPC.")
    ap.add_argument("--win-sni", default="win-test-01", help="TLS SNI/authority for LeechAgent server cert.")
    ap.add_argument("--grpc-port", type=int, default=28474)
    ap.add_argument("--server-ca", default="/data/ir/pki/ca.crt.pem", help="CA to verify LeechAgent server cert.")
    ap.add_argument("--client-p12", default="/data/ir/mtls/host-01/client_legacy.p12", help="Client PKCS#12 for mTLS.")
    ap.add_argument("--client-p12-password", default="changeit")
    ap.add_argument("--mount", default="/tmp/memprocfs")
    ap.add_argument("--memprocfs-bin", default="/data/tools/memprocfs/memprocfs")
    ap.add_argument("--memprocfs-libpath", default="/data/tools/memprocfs/current:/data/tools/memprocfs/lib")
    ap.add_argument("--forensic", type=int, default=1)
    ap.add_argument("--verbose", action="store_true", default=True)

    ap.add_argument("--buckets", default="/data/ir/yarahub_buckets.json")
    ap.add_argument("--rules-dir", default="/data/yaraify/rules")
    ap.add_argument("--out-dir", default="/data/yaraify/out")

    ap.add_argument("--min-range-mib", type=int, default=256, help="Skip tiny ranges below this size.")
    ap.add_argument("--print-interval-seconds", type=int, default=30)
    ap.add_argument("--stall-seconds", type=int, default=180)
    ap.add_argument("--mount-timeout-seconds", type=int, default=90)
    return ap.parse_args()


def _parse_status(txt: str) -> dict[str, object]:
    out: dict[str, object] = {}
    for line in txt.splitlines():
        line = line.strip()
        if line.startswith("Status:"):
            out["status"] = line.split(":", 1)[1].strip()
        elif line.startswith("Bytes read:"):
            v = line.split(":", 1)[1].strip()
            if v.lower().startswith("0x"):
                try:
                    out["bytes_read"] = int(v, 16)
                except Exception:
                    pass
        elif line.startswith("Speed (MB/s):"):
            v = line.split(":", 1)[1].strip()
            try:
                out["speed_mb_s"] = int(v)
            except Exception:
                pass
        elif line.startswith("Current address:"):
            out["current_address"] = line.split(":", 1)[1].strip()
    return out


def main() -> int:
    # When executed as a script (python /work/ir/scripts/...), Python's module search path
    # may not include the repo root (/work). Ensure `import ir...` works reliably.
    repo_root = Path(__file__).resolve().parents[2]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    args = _parse_args()

    mount = Path(args.mount)
    subprocess.run(["rm", "-rf", str(mount)], check=False)
    mount.mkdir(parents=True, exist_ok=True)

    # Ensure MemProcFS shared libs are found.
    os.environ["LD_LIBRARY_PATH"] = str(args.memprocfs_libpath)

    remote = (
        f"grpc://{args.win_sni}:{args.win_ip}:"
        f"server-cert={args.server_ca},"
        f"client-cert-p12={args.client_p12},"
        f"client-cert-p12-password={args.client_p12_password}"
    )

    cmd = [args.memprocfs_bin, "-mount", str(mount), "-device", "pmem", "-remote", remote]
    if int(args.forensic) == 1:
        cmd += ["-forensic", "1"]
    if bool(args.verbose):
        cmd += ["-v"]

    print("starting_memprocfs:", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=os.environ.copy())
    try:
        base = mount / "misc" / "search" / "yara"
        t0 = time.time()
        while not base.exists():
            if proc.poll() is not None:
                raise RuntimeError("MemProcFS exited early (check LeechAgent/pmem).")
            if time.time() - t0 > float(args.mount_timeout_seconds):
                raise RuntimeError("MemProcFS mount timeout.")
            print(f"waiting_for_mount... {int(time.time()-t0)}s", flush=True)
            time.sleep(1)

        from ir.worker.run import _read_physmemmap_ranges, ensure_high_mid_rules_merged

        print("building_rules_index...", flush=True)
        idx = ensure_high_mid_rules_merged(
            buckets_path=Path(args.buckets),
            rules_dir=Path(args.rules_dir),
            out_dir=Path(args.out_dir),
        )
        print("rules_index_ready", idx, flush=True)
        print("reading_physmemmap...", flush=True)
        ranges, phys = _read_physmemmap_ranges(mount_dir=mount)
        print(f"physmem_total_gib={phys.get('total_gib')} range_count={phys.get('range_count')}")
        print(f"rules_index={idx}")

        min_bytes = int(args.min_range_mib) * 1024 * 1024
        big = [(a, b) for (a, b) in ranges if (b - a + 1) >= min_bytes]
        if big:
            ranges = big
        print(f"scan_ranges={len(ranges)} min_range_mib={args.min_range_mib}")

        status_fp = base / "status.txt"
        reset_fp = base / "reset.txt"
        addr_min_fp = base / "addr-min.txt"
        addr_max_fp = base / "addr-max.txt"
        rules_fp = base / "yara-rules-file.txt"

        for i, (rbase, rtop) in enumerate(ranges, start=1):
            span = int(rtop - rbase + 1)
            print(f"\n[range {i}/{len(ranges)}] base=0x{rbase:x} top=0x{rtop:x} span_gib={span/1024/1024/1024:.3f}")

            # Start scan for this range
            reset_fp.write_text("1\n", encoding="utf-8")
            time.sleep(0.2)
            addr_min_fp.write_text(f"{rbase:016x}\n", encoding="utf-8")
            addr_max_fp.write_text(f"{rtop:016x}\n", encoding="utf-8")
            rules_fp.write_text(str(idx) + "\n", encoding="utf-8")

            last_br = None
            last_progress = time.time()
            started = time.time()
            while True:
                time.sleep(int(args.print_interval_seconds))
                try:
                    txt = status_fp.read_text(errors="replace")
                except Exception:
                    txt = ""
                s = _parse_status(txt)
                st = str(s.get("status") or "")
                br = s.get("bytes_read")
                sp = s.get("speed_mb_s")
                cur = s.get("current_address")

                pct = 0.0
                if isinstance(br, int) and span > 0:
                    pct = (br / span) * 100.0

                if isinstance(br, int) and (last_br is None or br != last_br):
                    last_br = br
                    last_progress = time.time()

                eta = "?"
                if isinstance(sp, int) and sp > 0 and isinstance(br, int):
                    remain = max(0, span - br)
                    eta_min = (remain / (sp * 1024 * 1024)) / 60.0
                    eta = f"{eta_min:.1f}m"

                elapsed_min = (time.time() - started) / 60.0
                br_hex = f"0x{br:x}" if isinstance(br, int) else "?"
                print(
                    f"t={elapsed_min:6.1f}m status={st} pct={pct:6.2f}% speed={sp}MB/s eta={eta} cur={cur} bytes={br_hex}"
                )

                if st.upper() == "COMPLETED":
                    break

                # Some MemProcFS builds keep Status=RUNNING briefly even after reaching the end.
                # If we've reached (or effectively reached) the span, treat as completed to avoid
                # false stall abort at 100%.
                if isinstance(br, int) and br >= max(0, span - 0x1000) and pct >= 99.99:
                    print("FORCE_COMPLETE: reached end of range (bytes_read ~= span)")
                    break

                if (time.time() - last_progress) > int(args.stall_seconds):
                    print(f"STALL: no progress for {args.stall_seconds}s -> abort current range")
                    reset_fp.write_text("1\n", encoding="utf-8")
                    break

        total_runtime = int(time.time() - t0)
        print(f"\nDONE total_runtime_seconds={total_runtime}")
        return 0
    finally:
        try:
            if (mount / "misc" / "search" / "yara" / "reset.txt").exists():
                (mount / "misc" / "search" / "yara" / "reset.txt").write_text("1\n", encoding="utf-8")
        except Exception:
            pass
        try:
            subprocess.run(["fusermount", "-u", str(mount)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        try:
            proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


if __name__ == "__main__":
    raise SystemExit(main())

