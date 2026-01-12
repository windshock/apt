from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "y", "on"}


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    db_path: Path
    evidence_dir: Path
    pki_dir: Path
    leechagent_tls_dir: Path
    shared_key: str
    require_signature: bool
    # UI (dashboard)
    ui_enabled: bool
    ui_user: str
    ui_password: str
    # WorkOrder defaults (production knobs)
    memprocfs_default_enabled: bool
    memprocfs_mount_base: Path
    memprocfs_keepalive_interval_seconds: int
    memprocfs_attempt_timeout_seconds: int
    memprocfs_max_attempts: int
    leechagent_grpc_port: int
    leechagent_override_host: str | None
    leechagent_override_server_name: str | None

    @staticmethod
    def load() -> "Settings":
        data_dir = Path(os.getenv("IR_DATA_DIR", "/data/ir")).resolve()
        db_path = Path(os.getenv("IR_DB_PATH", str(data_dir / "orchestrator.db"))).resolve()
        evidence_dir = Path(os.getenv("IR_EVIDENCE_DIR", str(data_dir / "evidence"))).resolve()
        pki_dir = Path(os.getenv("IR_PKI_DIR", str(data_dir / "pki"))).resolve()
        leechagent_tls_dir = Path(os.getenv("IR_LEECHAGENT_TLS_DIR", str(data_dir / "leechagent_tls"))).resolve()
        shared_key = os.getenv("IR_SHARED_KEY", "dev")
        require_signature = _env_bool("IR_REQUIRE_SIGNATURE", False)
        ui_enabled = _env_bool("IR_UI_ENABLED", True)
        ui_user = os.getenv("IR_UI_USER", "ir")
        ui_password = os.getenv("IR_UI_PASSWORD", "ir")
        memprocfs_default_enabled = _env_bool("IR_MEMPROCFS_DEFAULT_ENABLED", True)
        memprocfs_mount_base = Path(os.getenv("IR_MEMPROCFS_MOUNT_BASE", str(data_dir / "memprocfs_mount"))).resolve()
        memprocfs_keepalive_interval_seconds = int(os.getenv("IR_MEMPROCFS_KEEPALIVE_INTERVAL_SECONDS", "20"))
        memprocfs_attempt_timeout_seconds = int(os.getenv("IR_MEMPROCFS_ATTEMPT_TIMEOUT_SECONDS", "60"))
        memprocfs_max_attempts = int(os.getenv("IR_MEMPROCFS_MAX_ATTEMPTS", "2"))
        leechagent_grpc_port = int(os.getenv("IR_LEECHAGENT_GRPC_PORT", "28474"))
        leechagent_override_host = os.getenv("IR_LEECHAGENT_OVERRIDE_HOST")
        leechagent_override_server_name = os.getenv("IR_LEECHAGENT_OVERRIDE_SERVER_NAME")
        return Settings(
            data_dir=data_dir,
            db_path=db_path,
            evidence_dir=evidence_dir,
            pki_dir=pki_dir,
            leechagent_tls_dir=leechagent_tls_dir,
            shared_key=shared_key,
            require_signature=require_signature,
            ui_enabled=ui_enabled,
            ui_user=ui_user,
            ui_password=ui_password,
            memprocfs_default_enabled=memprocfs_default_enabled,
            memprocfs_mount_base=memprocfs_mount_base,
            memprocfs_keepalive_interval_seconds=memprocfs_keepalive_interval_seconds,
            memprocfs_attempt_timeout_seconds=memprocfs_attempt_timeout_seconds,
            memprocfs_max_attempts=memprocfs_max_attempts,
            leechagent_grpc_port=leechagent_grpc_port,
            leechagent_override_host=leechagent_override_host,
            leechagent_override_server_name=leechagent_override_server_name,
        )

