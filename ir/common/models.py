from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class CaseStatus(str, Enum):
    created = "created"
    waiting_agent = "waiting_agent"
    agent_joined = "agent_joined"
    work_order_issued = "work_order_issued"
    running = "running"
    completed = "completed"
    failed = "failed"


class YaraLevel(str, Enum):
    HIGH = "HIGH"
    MID = "MID"
    LOW = "LOW"


class ScopePolicy(str, Enum):
    vad_rwx_private = "vad_rwx_private"
    vad_exec = "vad_exec"
    all = "all"


class DumpPolicy(str, Enum):
    HIGH_ONLY = "HIGH_ONLY"
    HIGH_MID = "HIGH_MID"
    NONE = "NONE"


class CybereasonEvent(BaseModel):
    event_time: datetime
    endpoint_id: str
    hostname: str | None = None
    malop_id: str
    severity: str
    detection_type: str | None = None
    isolation_status: str | None = None


class CaseCreateRequest(BaseModel):
    source: Literal["cybereason"] = "cybereason"
    event: CybereasonEvent


class CaseCreateResponse(BaseModel):
    case_id: str
    case_key: str
    created: bool
    status: CaseStatus


class AgentJoinRequest(BaseModel):
    agent_id: str = Field(..., description="Stable endpoint identifier (e.g. endpoint_id)")
    hostname: str | None = None
    ip: str | None = None
    capabilities: dict[str, Any] = Field(default_factory=dict)


class AgentJoinResponse(BaseModel):
    accepted: bool
    message: str | None = None


class WorkOrder(BaseModel):
    case_id: str
    target_pids: list[int] | None = None
    scope_policy: ScopePolicy = ScopePolicy.vad_rwx_private
    yara_levels: list[YaraLevel] = Field(default_factory=lambda: [YaraLevel.HIGH, YaraLevel.MID])
    dump_policy: DumpPolicy = DumpPolicy.HIGH_ONLY
    dump_escalation: dict[str, Any] = Field(
        default_factory=lambda: {
            "full_dump_rule_count_gate": {"high_min": 2, "mid_min": 1},
            "full_dump_strong_high_gate": {"enabled": True, "mid_min": 1},
            "strong_high_exclude_prefixes": ["meth_", "pe_"],
            "strong_high_exclude_rules": ["DetectEncryptedVariants", "Sus_CMD_Powershell_Usage"],
            "note": "Do NOT auto-escalate on HIGH+MID+LOW; Low is a profiling signal only.",
        },
        description="Dump escalation policy knobs (MVP defaults aligned with design doc).",
    )
    yara_ruleset: str | None = Field(
        default=None,
        description="Worker-side identifier (e.g. 'yarahub.compiled' or path in /data).",
    )

    # Remote memory acquisition (LeechAgent + MemProcFS)
    leechagent: dict[str, Any] = Field(
        default_factory=lambda: {
            "mode": "grpc",
            "host": None,  # set by orchestrator when known (endpoint IP/DNS)
            "server_name": None,  # optional TLS authority/SNI name
            "port": 28474,
            "connect_timeout_seconds": 10,
        },
        description="How worker connects to endpoint LeechAgent. Default: gRPC 28474.",
    )
    memprocfs: dict[str, Any] = Field(
        default_factory=lambda: {
            "enabled": False,
            "binary": "/data/tools/memprocfs/memprocfs",
            "lib_dir": "/data/tools/memprocfs/lib",
            "mount_dir": "/tmp/memprocfs",
            "extra_args": [],
            # Reliability knobs (esp. for remote init instability)
            "max_attempts": 2,
            "attempt_timeout_seconds": 60,
            # LeechAgent server-side client keepalive timeout is ~75s upstream.
            # Keep this comfortably below that value.
            "keepalive_interval_seconds": 20,
            # If true, worker will build default args (pmem+remote TLS) automatically.
            "auto_build_args": True,
            # Client certificate for MemProcFS->LeechAgent mTLS (legacy p12 is generated if missing).
            "client_p12_path": None,
            "client_p12_password": "changeit",
            # Trust anchor for LeechAgent server cert validation.
            "server_ca_cert": "/data/ir/pki/ca.crt.pem",
            # Default device mode
            "device": "pmem",
            "forensic": True,
            "verbose": True,
            # Bound time spent in MemProcFS YaraSearch (avoid >75s idle + long hangs).
            # 0 means "no hard timeout"; use stall watchdog instead.
            "yara_timeout_seconds": 0,
            # If Bytes read / Current address does not change for this long, treat as hang.
            "yara_stall_timeout_seconds": 180,
            # Shutdown tuning
            "shutdown_sigint_wait_seconds": 60,
            "shutdown_sigterm_wait_seconds": 30,
        },
        description="MemProcFS execution settings. Enable when binaries are available.",
    )


class EvidenceManifest(BaseModel):
    case_id: str
    endpoint_id: str | None = None
    created_at: datetime
    files: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Each item should include name/path/sha256/size/created_at etc.",
    )


class ScanHit(BaseModel):
    rule: str
    level: YaraLevel | None = None
    target: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    case_id: str
    agent_id: str | None = None
    started_at: datetime
    finished_at: datetime
    scope_policy: ScopePolicy
    yara_levels: list[YaraLevel]
    dump_policy: DumpPolicy
    hits: list[ScanHit] = Field(default_factory=list)
    planned_actions: dict[str, Any] = Field(
        default_factory=dict,
        description="Worker decision summary: dump actions, escalation gates, etc.",
    )
    stats: dict[str, Any] = Field(default_factory=dict)

