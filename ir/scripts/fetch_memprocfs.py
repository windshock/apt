from __future__ import annotations

import argparse
import os
import platform
import tarfile
import zipfile
from pathlib import Path

import requests


REPO = "ufrisk/MemProcFS"


def _detect_platform_key() -> str:
    sysname = platform.system().lower()
    mach = platform.machine().lower()
    if sysname == "linux":
        if mach in {"x86_64", "amd64"}:
            return "linux_x64"
        if mach in {"aarch64", "arm64"}:
            return "linux_aarch64"
    if sysname == "darwin":
        return "macOS"
    raise RuntimeError(f"unsupported platform: {sysname}/{mach}")


def _github_latest_release() -> dict:
    url = f"https://api.github.com/repos/{REPO}/releases/latest"
    r = requests.get(url, timeout=30)
    r.raise_for_status()
    return r.json()


def _pick_asset(release: dict, platform_key: str) -> tuple[str, str]:
    assets = release.get("assets") or []
    # Prefer "files_and_binaries" for the platform.
    for a in assets:
        name = a.get("name") or ""
        url = a.get("browser_download_url") or ""
        if platform_key in name and ("files_and_binaries" in name.lower()):
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


def _extract(archive_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    name = archive_path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(archive_path, "r") as z:
            z.extractall(out_dir)
        return
    if name.endswith(".tar.gz") or name.endswith(".tgz"):
        with tarfile.open(archive_path, "r:gz") as t:
            t.extractall(out_dir)
        return
    raise RuntimeError(f"unsupported archive format: {archive_path.name}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Download and extract MemProcFS binaries into /data/tools/memprocfs.")
    ap.add_argument("--out-dir", default=os.getenv("MEMPROCFS_OUT_DIR", "/data/tools/memprocfs"))
    ap.add_argument("--platform", default=os.getenv("MEMPROCFS_PLATFORM", "auto"), help="auto|linux_x64|linux_aarch64|macOS")
    args = ap.parse_args()

    platform_key = _detect_platform_key() if args.platform == "auto" else args.platform
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rel = _github_latest_release()
    tag = rel.get("tag_name") or "unknown"
    asset_name, asset_url = _pick_asset(rel, platform_key)

    archive_path = out_dir / asset_name
    if not archive_path.exists():
        _download(asset_url, archive_path)
    extract_dir = out_dir / f"extract_{tag}_{platform_key}"
    if not extract_dir.exists():
        _extract(archive_path, extract_dir)

    # Create stable paths for other components.
    current = out_dir / "current"
    try:
        if current.is_symlink() or current.exists():
            current.unlink()
        current.symlink_to(extract_dir, target_is_directory=True)
    except Exception:
        # best-effort (symlinks may not be supported)
        pass

    memprocfs_bin = extract_dir / "memprocfs"
    stable_bin = out_dir / "memprocfs"
    if memprocfs_bin.exists():
        try:
            if stable_bin.is_symlink() or stable_bin.exists():
                stable_bin.unlink()
            stable_bin.symlink_to(memprocfs_bin)
        except Exception:
            pass

    print(f"tag={tag}")
    print(f"asset={asset_name}")
    print(f"saved={archive_path}")
    print(f"extracted={extract_dir}")
    if current.exists():
        print(f"current={current} -> {extract_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

