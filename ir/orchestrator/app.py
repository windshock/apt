from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Body, Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse

from ir.common.models import (
    AgentJoinRequest,
    AgentJoinResponse,
    CaseCreateResponse,
    CaseStatus,
    CybereasonEvent,
    WorkOrder,
)
from ir.orchestrator.config import Settings
from ir.orchestrator.db import OrchestratorDB
from ir.orchestrator.leechagent_tls import LeechAgentTLSIssuer
from ir.orchestrator.pki import PKIPaths, SimpleCA
from ir.orchestrator.security import require_auth, require_ui_auth, ui_basic_dep


def _case_key(endpoint_id: str, malop_id: str) -> str:
    return f"{endpoint_id}:{malop_id}"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _repo_root() -> Path:
    """
    Best-effort repo root locator for bootstrap artifact endpoints.
    In our container image we `COPY . /work`, so this typically resolves to `/work`.
    """
    # app.py -> orchestrator -> ir -> <repo root>
    return Path(__file__).resolve().parents[2]


def _windows_bootstrap_dir() -> Path:
    return (_repo_root() / "ir" / "agent" / "windows").resolve()


def _default_work_order(*, settings: Settings, case_id: str, agent: dict | None) -> WorkOrder:
    """
    Build an operational default work order:
    - Enable MemProcFS mount (can be disabled via env)
    - Set per-case mount directory
    - Set LeechAgent gRPC host/port (+ server_name for TLS SNI/authority)
    - Keepalive interval < 75s (LeechAgent client keepalive timeout in upstream)
    """
    wo = WorkOrder(case_id=case_id)

    # LeechAgent connection target (prefer agent IP)
    if settings.leechagent_override_host:
        wo.leechagent["host"] = settings.leechagent_override_host
    if settings.leechagent_override_server_name:
        wo.leechagent["server_name"] = settings.leechagent_override_server_name

    if agent:
        if not wo.leechagent.get("host") and agent.get("ip"):
            wo.leechagent["host"] = agent["ip"]
        if not wo.leechagent.get("server_name") and agent.get("hostname"):
            wo.leechagent["server_name"] = agent["hostname"]
    wo.leechagent["port"] = int(settings.leechagent_grpc_port)

    # MemProcFS defaults
    wo.memprocfs["enabled"] = bool(settings.memprocfs_default_enabled)
    wo.memprocfs["mount_dir"] = str((settings.memprocfs_mount_base / case_id).resolve())
    wo.memprocfs["keepalive_interval_seconds"] = int(settings.memprocfs_keepalive_interval_seconds)
    wo.memprocfs["attempt_timeout_seconds"] = int(settings.memprocfs_attempt_timeout_seconds)
    wo.memprocfs["max_attempts"] = int(settings.memprocfs_max_attempts)
    # Let worker auto-build memprocfs args (remote string, client p12, etc.)
    wo.memprocfs["auto_build_args"] = True
    return wo


def create_app() -> FastAPI:
    settings = Settings.load()
    db = OrchestratorDB(settings.db_path)
    db.init()
    settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    ca = SimpleCA(PKIPaths.under(settings.pki_dir))
    ca.ensure_ca()
    leech_tls = LeechAgentTLSIssuer(pki_dir=settings.pki_dir, out_dir=settings.leechagent_tls_dir)

    app = FastAPI(title="IR Orchestrator", version="0.1.0")

    async def _auth_dep(request: Request) -> str:
        return await require_auth(request, settings)

    basic = ui_basic_dep()

    def _hit_counts(result: dict) -> dict[str, int]:
        """
        Best-effort: count hits by level from ScanResult payload.
        """
        hits = result.get("hits") or []
        high = 0
        mid = 0
        low = 0
        for h in hits:
            lvl = (h or {}).get("level")
            if lvl == "HIGH":
                high += 1
            elif lvl == "MID":
                mid += 1
            elif lvl == "LOW":
                low += 1
        return {"high": high, "mid": mid, "low": low, "total": len(hits)}

    def _ui_page() -> str:
        # Simple self-contained HTML (no external assets) + auto-refresh polling.
        return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>IR Dashboard</title>
  <style>
    body{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; margin:16px; color:#111;}
    h1{font-size:18px; margin:0 0 12px;}
    .bar{display:flex; gap:12px; align-items:center; margin:8px 0 14px;}
    .muted{color:#666; font-size:12px;}
    .pill{padding:2px 8px; border-radius:999px; font-size:12px; background:#f3f4f6;}
    table{border-collapse:collapse; width:100%;}
    th,td{border-bottom:1px solid #e5e7eb; padding:8px; font-size:12px; vertical-align:top;}
    th{text-align:left; color:#374151; position:sticky; top:0; background:#fff;}
    tr:hover{background:#fafafa;}
    a{color:#2563eb; text-decoration:none;}
    a:hover{text-decoration:underline;}
    code{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; font-size:11px;}
    .status{font-weight:600;}
  </style>
</head>
<body>
  <h1>IR Dashboard</h1>
  <div class="bar">
    <span class="pill" id="caseCount">cases: -</span>
    <span class="pill" id="lastUpdated">updated: -</span>
    <span class="muted">Auto-refresh: 5s</span>
  </div>
  <table>
    <thead>
      <tr>
        <th>updated</th>
        <th>status</th>
        <th>endpoint</th>
        <th>malop</th>
        <th>case_id</th>
        <th>hits (H/M/L)</th>
        <th>links</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>
  <script>
    async function load(){
      const r = await fetch('/ui/api/cases');
      if(!r.ok){
        document.getElementById('rows').innerHTML = '<tr><td colspan="7">failed to load: ' + r.status + '</td></tr>';
        return;
      }
      const data = await r.json();
      const rows = data.cases || [];
      document.getElementById('caseCount').textContent = 'cases: ' + rows.length;
      document.getElementById('lastUpdated').textContent = 'updated: ' + new Date().toISOString();
      const tb = document.getElementById('rows');
      tb.innerHTML = '';
      for(const c of rows){
        const tr = document.createElement('tr');
        const hits = (c.hit_counts ? (c.hit_counts.high + '/' + c.hit_counts.mid + '/' + c.hit_counts.low) : '-');
        tr.innerHTML =
          '<td><code>' + (c.updated_at || '') + '</code></td>' +
          '<td class="status">' + (c.status || '') + '</td>' +
          '<td>' + (c.endpoint_id || '') + '</td>' +
          '<td>' + (c.malop_id || '') + '</td>' +
          '<td><code>' + (c.case_id || '') + '</code></td>' +
          '<td>' + hits + '</td>' +
          '<td>' +
            '<a href="/ui/api/cases/' + c.case_id + '" target="_blank">detail</a>' +
          '</td>';
        tb.appendChild(tr);
      }
    }
    load();
    setInterval(load, 5000);
  </script>
</body>
</html>"""

    @app.get("/healthz")
    async def healthz():
        return {"ok": True}

    @app.get("/ui", response_class=HTMLResponse)
    async def ui_root(credentials=Depends(basic)):
        require_ui_auth(credentials, settings)
        return HTMLResponse(content=_ui_page())

    @app.get("/ui/api/cases")
    async def ui_cases(credentials=Depends(basic)):
        require_ui_auth(credentials, settings)
        rows = db.list_cases(limit=500)
        out = []
        for c in rows:
            r = db.get_result(case_id=c["case_id"])
            hit_counts = _hit_counts(r) if r else None
            out.append(
                {
                    "case_id": c.get("case_id"),
                    "case_key": c.get("case_key"),
                    "status": c.get("status"),
                    "endpoint_id": c.get("endpoint_id"),
                    "malop_id": c.get("malop_id"),
                    "created_at": c.get("created_at"),
                    "updated_at": c.get("updated_at"),
                    "has_result": bool(r),
                    "result_received_at": (r or {}).get("_received_at") if r else None,
                    "hit_counts": hit_counts,
                }
            )
        return {"cases": out}

    @app.get("/ui/api/cases/{case_id}")
    async def ui_case_detail(case_id: str, credentials=Depends(basic)):
        require_ui_auth(credentials, settings)
        case = db.get_case(case_id=case_id)
        if not case:
            raise HTTPException(status_code=404, detail="case not found")
        event = {}
        try:
            event = json.loads(case.get("event_json") or "{}")
        except Exception:
            event = {}
        wo = db.get_work_order(case_id=case_id)
        result = db.get_result(case_id=case_id)
        audit = db.list_audit(case_id=case_id, limit=200)
        return {
            "case": {k: v for k, v in case.items() if k != "event_json"},
            "event": event,
            "work_order": wo,
            "result": result,
            "hit_counts": (_hit_counts(result) if result else None),
            "audit": audit,
        }

    @app.get("/v1/pki/ca.crt.pem")
    async def get_ca_cert(_key: str = Depends(_auth_dep)):
        return {"ca_pem": ca.ca_pem().decode("utf-8")}

    # Bootstrap endpoints (no client cert). Intended to be exposed ONLY via gateway's enroll port (8443).
    @app.get("/bootstrap/ca.crt.pem")
    async def bootstrap_ca_cert():
        # CA public cert is not a secret; this enables "download CA + run installer from dfir.skplanet.com".
        return FileResponse(path=str(ca.paths.ca_cert), media_type="application/x-pem-file", filename="ca.crt.pem")

    @app.get("/bootstrap/windows/install_ir_agent.ps1")
    async def bootstrap_windows_install_ps1():
        p = _windows_bootstrap_dir() / "install_ir_agent.ps1"
        if not p.exists():
            raise HTTPException(status_code=404, detail="bootstrap asset not found")
        return FileResponse(path=str(p), media_type="text/plain; charset=utf-8", filename="install_ir_agent.ps1")

    @app.get("/bootstrap/windows/run_ir_agent.ps1")
    async def bootstrap_windows_run_ps1():
        p = _windows_bootstrap_dir() / "run_ir_agent.ps1"
        if not p.exists():
            raise HTTPException(status_code=404, detail="bootstrap asset not found")
        return FileResponse(path=str(p), media_type="text/plain; charset=utf-8", filename="run_ir_agent.ps1")

    @app.get("/bootstrap/windows/install_schtask.ps1")
    async def bootstrap_windows_install_schtask_ps1():
        p = _windows_bootstrap_dir() / "install_schtask.ps1"
        if not p.exists():
            raise HTTPException(status_code=404, detail="bootstrap asset not found")
        return FileResponse(path=str(p), media_type="text/plain; charset=utf-8", filename="install_schtask.ps1")

    @app.get("/bootstrap/windows/uninstall_schtask.ps1")
    async def bootstrap_windows_uninstall_schtask_ps1():
        p = _windows_bootstrap_dir() / "uninstall_schtask.ps1"
        if not p.exists():
            raise HTTPException(status_code=404, detail="bootstrap asset not found")
        return FileResponse(path=str(p), media_type="text/plain; charset=utf-8", filename="uninstall_schtask.ps1")

    @app.get("/bootstrap/windows/README.txt")
    async def bootstrap_windows_readme():
        txt = (
            "IR Agent bootstrap (Windows)\n"
            "\n"
            "Download CA:\n"
            "  GET /bootstrap/ca.crt.pem\n"
            "\n"
            "Download scripts:\n"
            "  GET /bootstrap/windows/install_ir_agent.ps1\n"
            "  GET /bootstrap/windows/run_ir_agent.ps1\n"
            "  GET /bootstrap/windows/install_schtask.ps1\n"
            "  GET /bootstrap/windows/uninstall_schtask.ps1\n"
        )
        return PlainTextResponse(content=txt, media_type="text/plain; charset=utf-8")

    @app.post("/v1/pki/enroll")
    async def enroll_client_cert(request: Request, _key: str = Depends(_auth_dep)):
        """
        MVP enrollment: client sends CSR PEM, server returns signed client cert + CA.
        NOTE: In production, use a stronger bootstrap mechanism than shared key.
        """
        body = await request.json()
        csr_pem = (body.get("csr_pem") or "").encode("utf-8")
        days = int(body.get("days") or 90)
        if not csr_pem.strip().startswith(b"-----BEGIN CERTIFICATE REQUEST-----"):
            raise HTTPException(status_code=400, detail="csr_pem required")
        try:
            cert_pem = ca.sign_csr(csr_pem, days=days).decode("utf-8")
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"csr_invalid: {type(e).__name__}")
        db.audit(actor="agent", action="pki_enroll", case_id=None, detail={"days": days})
        return {"cert_pem": cert_pem, "ca_pem": ca.ca_pem().decode("utf-8")}

    @app.post("/v1/leechagent/{agent_id}/grpc-tls")
    async def issue_leechagent_grpc_tls(
        agent_id: str,
        request: Request,
        _key: str = Depends(_auth_dep),
    ):
        """
        Generate server.p12 + client_ca.pem for Windows LeechAgent gRPC (28474).
        By default uses the agent record (hostname/ip) captured at join.
        """
        body = await request.json()
        agent = db.get_agent(agent_id=agent_id)
        host = (body.get("host") or (agent.get("hostname") if agent else None) or agent_id)
        ip = body.get("ip") or (agent.get("ip") if agent else None)
        p12_password = body.get("p12_password")  # optional; if absent, server generates
        days = int(body.get("days") or 365)

        bundle = leech_tls.issue(host=host, ip=ip, p12_password=p12_password, days=days, write_files=True)
        db.audit(actor="orchestrator", action="leechagent_tls_issued", case_id=None, detail={"agent_id": agent_id, "host": host, "ip": ip})

        # Return content so the caller can directly download/copy to Windows.
        return {
            "host": bundle.host,
            "ip": bundle.ip,
            "p12_password": bundle.p12_password,
            "server_p12_b64": bundle.server_p12_b64(),
            "client_ca_pem": bundle.client_ca_pem_str(),
            "server_crt_pem": bundle.server_crt_pem_str(),
            "saved_dir": str((settings.leechagent_tls_dir / bundle.host).resolve()),
        }

    @app.post("/v1/events/cybereason", response_model=CaseCreateResponse)
    async def ingest_cybereason_event(evt: CybereasonEvent, _key: str = Depends(_auth_dep)):
        case_id = str(uuid.uuid4())
        case_key = _case_key(evt.endpoint_id, evt.malop_id)
        created, row = db.get_or_create_case(
            case_id=case_id,
            case_key=case_key,
            endpoint_id=evt.endpoint_id,
            malop_id=evt.malop_id,
            status=CaseStatus.waiting_agent.value,
            event=json.loads(evt.model_dump_json()),
        )
        db.audit(
            actor="cybereason",
            action="case_create" if created else "case_exists",
            case_id=row["case_id"],
            detail={"case_key": case_key, "created": created},
        )
        return CaseCreateResponse(
            case_id=row["case_id"],
            case_key=row["case_key"],
            created=created,
            status=CaseStatus(row["status"]),
        )

    @app.post("/v1/agents/join", response_model=AgentJoinResponse)
    async def agent_join(payload: AgentJoinRequest, request: Request, _key: str = Depends(_auth_dep)):
        client_ip = request.client.host if request.client else None
        # When behind a proxy/gateway, prefer X-Forwarded-For if present.
        xff = (request.headers.get("x-forwarded-for") or "").split(",")[0].strip()
        ip = payload.ip or xff or client_ip
        db.upsert_agent(
            agent_id=payload.agent_id,
            hostname=payload.hostname,
            ip=ip,
            capabilities=payload.capabilities,
        )
        case = db.find_active_case_for_agent(agent_id=payload.agent_id)
        if not case:
            db.audit(
                actor=payload.agent_id,
                action="agent_join_no_case",
                case_id=None,
                detail={"agent_id": payload.agent_id},
            )
            return AgentJoinResponse(accepted=False, message="no active case for agent")
        if case["status"] in {CaseStatus.created.value, CaseStatus.waiting_agent.value}:
            db.update_case_status(case_id=case["case_id"], status=CaseStatus.agent_joined.value)
        db.audit(
            actor=payload.agent_id,
            action="agent_join",
            case_id=case["case_id"],
            detail={"agent_id": payload.agent_id},
        )
        return AgentJoinResponse(accepted=True, message=f"joined case {case['case_id']}")

    @app.get("/v1/agents/{agent_id}/work-orders/next", response_model=WorkOrder)
    async def next_work_order(agent_id: str, _key: str = Depends(_auth_dep)):
        case = db.find_active_case_for_agent(agent_id=agent_id)
        if not case:
            raise HTTPException(status_code=404, detail="no active case")
        existing = db.get_work_order(case_id=case["case_id"])
        if existing:
            return WorkOrder.model_validate(existing)

        agent = db.get_agent(agent_id=agent_id)
        wo = _default_work_order(settings=settings, case_id=case["case_id"], agent=agent)
        db.set_work_order(case_id=case["case_id"], work_order=json.loads(wo.model_dump_json()))
        db.update_case_status(case_id=case["case_id"], status=CaseStatus.work_order_issued.value)
        db.audit(actor="orchestrator", action="work_order_issued", case_id=case["case_id"], detail={})
        return wo

    @app.get("/v1/cases/{case_id}/work-order", response_model=WorkOrder)
    async def get_work_order_by_case(case_id: str, _key: str = Depends(_auth_dep)):
        case = db.get_case(case_id=case_id)
        if not case:
            raise HTTPException(status_code=404, detail="case not found")
        existing = db.get_work_order(case_id=case_id)
        if existing:
            return WorkOrder.model_validate(existing)

        agent = db.get_agent(agent_id=case["endpoint_id"])
        wo = _default_work_order(settings=settings, case_id=case_id, agent=agent)
        db.set_work_order(case_id=case_id, work_order=json.loads(wo.model_dump_json()))
        if case["status"] in {
            CaseStatus.created.value,
            CaseStatus.waiting_agent.value,
            CaseStatus.agent_joined.value,
        }:
            db.update_case_status(case_id=case_id, status=CaseStatus.work_order_issued.value)
        db.audit(actor="orchestrator", action="work_order_issued", case_id=case_id, detail={"by": "case_id"})
        return wo

    @app.put("/v1/cases/{case_id}/work-order", response_model=WorkOrder)
    async def put_work_order_by_case(
        case_id: str,
        wo: WorkOrder = Body(...),
        _key: str = Depends(_auth_dep),
    ):
        case = db.get_case(case_id=case_id)
        if not case:
            raise HTTPException(status_code=404, detail="case not found")
        if wo.case_id != case_id:
            raise HTTPException(status_code=400, detail="case_id mismatch")
        db.set_work_order(case_id=case_id, work_order=json.loads(wo.model_dump_json()))
        db.update_case_status(case_id=case_id, status=CaseStatus.work_order_issued.value)
        db.audit(actor="orchestrator", action="work_order_overridden", case_id=case_id, detail={})
        return wo

    @app.post("/v1/cases/{case_id}/results")
    async def upload_results(case_id: str, request: Request, _key: str = Depends(_auth_dep)):
        body = await request.json()
        case = db.get_case(case_id=case_id)
        if not case:
            raise HTTPException(status_code=404, detail="case not found")
        db.save_result(case_id=case_id, result=body)
        db.update_case_status(case_id=case_id, status=CaseStatus.completed.value)
        db.audit(actor="worker", action="results_uploaded", case_id=case_id, detail={})

        # also persist a copy into evidence dir
        out_dir = settings.evidence_dir / case_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "result.json").write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"ok": True}

    @app.post("/v1/cases/{case_id}/manifest")
    async def upload_manifest(case_id: str, request: Request, _key: str = Depends(_auth_dep)):
        body = await request.json()
        case = db.get_case(case_id=case_id)
        if not case:
            raise HTTPException(status_code=404, detail="case not found")
        out_dir = settings.evidence_dir / case_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "manifest.json").write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        db.audit(actor="worker", action="manifest_uploaded", case_id=case_id, detail={})
        return {"ok": True}

    @app.post("/v1/cases/{case_id}/evidence")
    async def upload_evidence(case_id: str, file: UploadFile = File(...), _key: str = Depends(_auth_dep)):
        case = db.get_case(case_id=case_id)
        if not case:
            raise HTTPException(status_code=404, detail="case not found")
        out_dir = settings.evidence_dir / case_id / "files"
        out_dir.mkdir(parents=True, exist_ok=True)
        safe_name = Path(file.filename or "evidence.bin").name
        out_path = out_dir / safe_name
        content = await file.read()
        out_path.write_bytes(content)
        db.audit(
            actor="worker",
            action="evidence_uploaded",
            case_id=case_id,
            detail={"name": safe_name, "size": len(content)},
        )
        return {"ok": True, "name": safe_name, "size": len(content)}

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(_request: Request, exc: Exception):
        # keep responses predictable for agents/workers
        return JSONResponse(status_code=500, content={"detail": f"internal_error: {type(exc).__name__}"})

    return app


app = create_app()

