from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS cases (
  case_id TEXT PRIMARY KEY,
  case_key TEXT NOT NULL UNIQUE,
  status TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  malop_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  event_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cases_endpoint_status ON cases(endpoint_id, status);

CREATE TABLE IF NOT EXISTS agents (
  agent_id TEXT PRIMARY KEY,
  hostname TEXT,
  ip TEXT,
  last_seen_at TEXT NOT NULL,
  capabilities_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS work_orders (
  case_id TEXT PRIMARY KEY,
  work_order_json TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  FOREIGN KEY(case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS results (
  case_id TEXT PRIMARY KEY,
  result_json TEXT NOT NULL,
  received_at TEXT NOT NULL,
  FOREIGN KEY(case_id) REFERENCES cases(case_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  case_id TEXT,
  detail_json TEXT NOT NULL
);
"""


class OrchestratorDB:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(str(self.db_path))
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def init(self) -> None:
        with self.connect() as con:
            con.executescript(SCHEMA)

    def audit(self, *, actor: str | None, action: str, case_id: str | None, detail: dict[str, Any]) -> None:
        with self.connect() as con:
            con.execute(
                "INSERT INTO audit_log(ts, actor, action, case_id, detail_json) VALUES (?, ?, ?, ?, ?)",
                (utc_now_iso(), actor, action, case_id, json.dumps(detail, ensure_ascii=False)),
            )

    def get_or_create_case(
        self,
        *,
        case_id: str,
        case_key: str,
        endpoint_id: str,
        malop_id: str,
        status: str,
        event: dict[str, Any],
    ) -> tuple[bool, dict[str, Any]]:
        now = utc_now_iso()
        with self.connect() as con:
            row = con.execute("SELECT * FROM cases WHERE case_key = ?", (case_key,)).fetchone()
            if row:
                return False, dict(row)
            con.execute(
                """
                INSERT INTO cases(case_id, case_key, status, endpoint_id, malop_id, created_at, updated_at, event_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (case_id, case_key, status, endpoint_id, malop_id, now, now, json.dumps(event, ensure_ascii=False)),
            )
            row2 = con.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            return True, dict(row2)

    def update_case_status(self, *, case_id: str, status: str) -> None:
        with self.connect() as con:
            con.execute("UPDATE cases SET status = ?, updated_at = ? WHERE case_id = ?", (status, utc_now_iso(), case_id))

    def upsert_agent(self, *, agent_id: str, hostname: str | None, ip: str | None, capabilities: dict[str, Any]) -> None:
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO agents(agent_id, hostname, ip, last_seen_at, capabilities_json)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                  hostname=excluded.hostname,
                  ip=excluded.ip,
                  last_seen_at=excluded.last_seen_at,
                  capabilities_json=excluded.capabilities_json
                """,
                (agent_id, hostname, ip, utc_now_iso(), json.dumps(capabilities, ensure_ascii=False)),
            )

    def get_agent(self, *, agent_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            return dict(row) if row else None

    def find_active_case_for_agent(self, *, agent_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute(
                """
                SELECT * FROM cases
                WHERE endpoint_id = ?
                  AND status IN ('created', 'waiting_agent', 'agent_joined', 'work_order_issued', 'running')
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (agent_id,),
            ).fetchone()
            return dict(row) if row else None

    def get_case(self, *, case_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,)).fetchone()
            return dict(row) if row else None

    def list_cases(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM cases ORDER BY updated_at DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_result(self, *, case_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT result_json, received_at FROM results WHERE case_id = ?", (case_id,)).fetchone()
            if not row:
                return None
            obj = json.loads(row["result_json"])
            obj["_received_at"] = row["received_at"]
            return obj

    def list_audit(self, *, case_id: str | None = None, limit: int = 200) -> list[dict[str, Any]]:
        with self.connect() as con:
            if case_id:
                rows = con.execute(
                    "SELECT * FROM audit_log WHERE case_id = ? ORDER BY id DESC LIMIT ?",
                    (case_id, int(limit)),
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                    (int(limit),),
                ).fetchall()
            out: list[dict[str, Any]] = []
            for r in rows:
                d = dict(r)
                try:
                    d["detail"] = json.loads(d.get("detail_json") or "{}")
                except Exception:
                    d["detail"] = {}
                d.pop("detail_json", None)
                out.append(d)
            return out

    def set_work_order(self, *, case_id: str, work_order: dict[str, Any]) -> None:
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO work_orders(case_id, work_order_json, issued_at)
                VALUES (?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                  work_order_json=excluded.work_order_json,
                  issued_at=excluded.issued_at
                """,
                (case_id, json.dumps(work_order, ensure_ascii=False), utc_now_iso()),
            )

    def get_work_order(self, *, case_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT work_order_json FROM work_orders WHERE case_id = ?", (case_id,)).fetchone()
            return json.loads(row["work_order_json"]) if row else None

    def save_result(self, *, case_id: str, result: dict[str, Any]) -> None:
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO results(case_id, result_json, received_at)
                VALUES (?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                  result_json=excluded.result_json,
                  received_at=excluded.received_at
                """,
                (case_id, json.dumps(result, ensure_ascii=False), utc_now_iso()),
            )

