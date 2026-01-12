from __future__ import annotations

import argparse
import os
import platform
import zipfile
from pathlib import Path

import requests


REPO = "ufrisk/libleechgrpc"


def _detect_platform_key() -> str:
    sysname = platform.system().lower()
    mach = platform.machine().lower()
    if sysname == "linux":
        if mach in {"x86_64", "amd64"}:
            return "linux_x64"
        if mach in {"aarch64", "arm64"}:
            return "linux_aarch64"
    raise RuntimeError(f"unsupported platform: {sysname}/{mach}")


def _github_latest_release() -> dict:
    url = f"https://api.github.com/repos/{REPO}/releases/latest"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()


def _pick_asset(release: dict, platform_key: str) -> tuple[str, str]:
    assets = release.get("assets") or []
    for a in assets:
        name = a.get("name") or ""
        url = a.get("browser_download_url") or ""
        if platform_key in name and name.lower().endswith(".zip"):
            return name, url
    raise RuntimeError(f"no asset found for {platform_key}")


def _download(url: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with requests.get(url, stream=True, timeout=300) as r:
        r.raise_for_status()
        with out_path.open("wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    f.write(chunk)


def main() -> int:
    ap = argparse.ArgumentParser(description="Download libleechgrpc for MemProcFS gRPC remoting.")
    ap.add_argument("--out-dir", default=os.getenv("LEECHGRPC_OUT_DIR", "/data/tools/memprocfs/lib"))
    ap.add_argument("--platform", default=os.getenv("LEECHGRPC_PLATFORM", "auto"), help="auto|linux_x64|linux_aarch64")
    args = ap.parse_args()

    platform_key = _detect_platform_key() if args.platform == "auto" else args.platform
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rel = _github_latest_release()
    tag = rel.get("tag_name") or "unknown"
    asset_name, asset_url = _pick_asset(rel, platform_key)

    zip_path = out_dir / asset_name
    if not zip_path.exists():
        _download(asset_url, zip_path)

    # Extract and locate .so
    extract_dir = out_dir / f"extract_{tag}_{platform_key}"
    if not extract_dir.exists():
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(extract_dir)

    so_candidates = list(extract_dir.rglob("libleechgrpc.so"))
    if not so_candidates:
        raise RuntimeError("libleechgrpc.so not found in extracted zip")
    so_src = so_candidates[0]
    so_dst = out_dir / "libleechgrpc.so"
    so_dst.write_bytes(so_src.read_bytes())

    print(f"tag={tag}")
    print(f"asset={asset_name}")
    print(f"saved={zip_path}")
    print(f"extracted={extract_dir}")
    print(f"installed={so_dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

