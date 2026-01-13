## IR: Automated Post-Isolation Memory Analysis (MVP)

This folder implements the design in `격리_이후_자동_메모리_분석_워크플로우_개발요구사항.md`.

### Components

- **Orchestrator** (`ir/orchestrator`): REST API + SQLite state DB + evidence storage.
- **Worker** (`ir/worker`): per-case runner that executes scan + uploads results/evidence.
- **Agent** (`ir/agent`): endpoint-side stub that checks "isolation" and joins orchestrator.

### Quick start (Docker)

1) Build image:

```bash
docker compose build
```

2) Run orchestrator + demo agent:

```bash
docker compose -f docker-compose.ir.yml up
```

This will also create:
- YaraHub buckets: `/data/ir/yarahub_buckets.json`
- MVP internal CA: `/data/ir/pki/ca.*.pem`
- MVP gateway server cert: `/data/ir/pki/server.*.pem`
- Demo agent mTLS material (CSR-based enrollment): `/data/ir/mtls/<agent_id>/client.*.pem`

Network (local compose):
- `https://localhost:443`: Orchestrator API (mTLS required; shared key still required in MVP)
- `https://localhost:8443`: Enrollment-only endpoints (no client cert; shared key required)
  - Bootstrap assets (no client cert): `/bootstrap/ca.crt.pem`, `/bootstrap/windows/*.ps1`

3) Create a case (simulate Cybereason trigger):

```bash
curl -sS -X POST "http://localhost:8080/v1/events/cybereason" \
  -H "Content-Type: application/json" \
  -H "X-IR-Key: dev" \
  -d '{"event_time":"2026-01-09T00:00:00Z","endpoint_id":"host-01","hostname":"host-01","malop_id":"m-1","severity":"HIGH","detection_type":"demo","isolation_status":"isolated"}' | jq .
```

4) Run worker once (demo mode):

```bash
docker compose -f docker-compose.ir.yml run --rm ir-worker \
  python3 -m ir.worker.run --case-id "<case_id_from_step_3>"
```

Artifacts:
- SQLite: `/data/ir/orchestrator.db` (inside container volume)
- Evidence: `/data/ir/evidence/<case_id>/...`

### Dashboard (Orchestrator UI)

The orchestrator exposes a simple dashboard at:
- `http://localhost:8080/ui` (when accessing `ir-orchestrator` directly), or
- `https://localhost:443/ui` (when going through `ir-gateway` / mTLS)

UI auth uses HTTP Basic:
- user: `IR_UI_USER` (default: `ir`)
- pass: `IR_UI_PASSWORD` (default: `ir`)

To disable the UI entirely: `IR_UI_ENABLED=0`.

### Network decisions (production)

- **LeechAgent ↔ Worker**: gRPC over **TCP 28474** (DFIR server → isolated PC)
- **Agent/Worker ↔ Orchestrator**: HTTPS **mTLS** recommended
  - Enrollment is CSR-based: agent generates key locally, server signs CSR.
  - Replace MVP internal CA with enterprise PKI when moving to production.

### Operational notes (important)

- **Time sync is mandatory (Windows endpoint)**:
  - If Windows clock is skewed, LeechAgent mTLS can fail with `certificate verify failed`
    due to `notBefore/notAfter` checks.
- **LeechAgent client keepalive timeout (~75s)**:
  - Upstream LeechAgent enforces a client keepalive timeout (`75*1000ms`).
  - Worker mitigates this by periodically touching the mounted MemProcFS view.
  - Tune via `WorkOrder.memprocfs.keepalive_interval_seconds` (default `20` seconds).
- **MemProcFS shared libraries**:
  - MemProcFS ships core `.so` (e.g. `vmm.so`) next to the binary and additional libs (e.g. `libleechgrpc.so`) in `lib/`.
  - Worker sets `LD_LIBRARY_PATH` to include both the MemProcFS extract dir and the `lib_dir`.

### When you will need a real Windows test endpoint

You can keep developing server-side logic without Windows, but you will need a Windows PC/VM when you want to validate:

- **LeechAgent actually runs on Windows** (service/driver/privileges)
- **Network allow**: DFIR server → Windows endpoint **TCP 28474**
- **MemProcFS remote memory access** succeeds (worker can read memory through LeechAgent)
- **Real dump generation** (process dump / full dump) and upload to evidence storage

### Windows endpoint PoC checklist (what you must do on the PC)

On the Windows PC/VM (isolated endpoint):

- **Time sync**: ensure NTP/time is correct (mTLS will fail if the clock is skewed).
- **Network allow** (while still “isolated” from the internet):
  - Endpoint → DFIR Orchestrator/Gateway: `443/tcp` (and `8443/tcp` for enrollment if used)
  - DFIR Worker (server) → Endpoint LeechAgent: `28474/tcp`
- **Prepare IR Agent runtime**:
  - PoC option: install Python 3.11+ and required deps (`requests`, `cryptography`).
  - Deploy helper scripts from this repo:
    - `ir/agent/windows/install_ir_agent.ps1`
    - `ir/agent/windows/run_ir_agent.ps1`
- **(Optional) Prepare LeechAgent**:
  - Place `leechagent.exe` (and required DLLs) on the endpoint.
  - Configure IR Agent to start it on isolation (`IR_LEECHAGENT_PATH`, `IR_LEECHAGENT_ARGS`).
  - The agent can also fetch gRPC TLS artifacts (`server.p12` + `client_ca.pem`) via orchestrator:
    - enable `IR_FETCH_LEECHAGENT_TLS=1` (default in the Windows installer script)

### Windows: make the agent run automatically (Scheduled Task, run-once)

For PoC, the simplest "always ready but low overhead" model is a Scheduled Task that runs the agent
in **run-once** mode periodically + at startup/logon:

1) Copy the repo's Windows scripts to the endpoint (or directly use them from a shared folder):
- `ir/agent/windows/install_ir_agent.ps1`
- `ir/agent/windows/run_ir_agent.ps1`
- `ir/agent/windows/install_schtask.ps1`
- `ir/agent/windows/uninstall_schtask.ps1`

Alternatively (recommended): download them from the DFIR server (bootstrap port, no client cert):

```powershell
Invoke-WebRequest -UseBasicParsing -Uri "https://dfir.skplanet.com:8443/bootstrap/windows/install_ir_agent.ps1" -OutFile .\install_ir_agent.ps1
Invoke-WebRequest -UseBasicParsing -Uri "https://dfir.skplanet.com:8443/bootstrap/windows/run_ir_agent.ps1" -OutFile .\run_ir_agent.ps1
Invoke-WebRequest -UseBasicParsing -Uri "https://dfir.skplanet.com:8443/bootstrap/windows/install_schtask.ps1" -OutFile .\install_schtask.ps1
Invoke-WebRequest -UseBasicParsing -Uri "https://dfir.skplanet.com:8443/bootstrap/windows/uninstall_schtask.ps1" -OutFile .\uninstall_schtask.ps1
```

2) Install config + firewall rule:

```powershell
.\install_ir_agent.ps1 -InstallDir "C:\ProgramData\IRAgent" `
  -OrchUrl "https://dfir.skplanet.com:30443" `
  -EnrollUrl "https://dfir.skplanet.com:30444" `
  -SharedKey "dev"
```

3) Install Scheduled Task (runs as SYSTEM):

```powershell
.\install_schtask.ps1 -InstallDir "C:\ProgramData\IRAgent" -TaskName "IRAgent" -EveryMinutes 1
```

To remove the task:

```powershell
.\uninstall_schtask.ps1 -TaskName "IRAgent"
```

### Windows: build a standalone EXE (recommended for PoC/rollout)

You cannot cross-compile a Windows EXE from Linux/macOS. Build on a Windows machine/VM:

```powershell
# From the repo checkout:
.\ir\agent\windows\build_ir_agent_exe.ps1

# Result:
#   .\dist\ir-agent.exe
```

Then deploy `ir-agent.exe` to the endpoint and run it with the same flags (or via the Scheduled Task wrapper).

#### Expected placement (PoC)

- Put MemProcFS binaries inside the DFIR server and mount into worker container at:
  - `/data/tools/memprocfs/memprocfs` (default in `WorkOrder.memprocfs.binary`)
- Ensure `WorkOrder.leechagent.host` resolves to the endpoint IP/DNS.

#### Dump artifact pipeline (pre-wired)

Before Windows is available, the worker is already wired to upload any files found under:
- `${IR_DUMP_DIR}/${case_id}/`

Default in compose:
- `/data/ir/dumps_inbox/<case_id>/...`

Once you integrate real dump generation, simply write dump files into that folder and they will be uploaded via `/v1/cases/{case_id}/evidence` and listed in `manifest.json`.

### Generate LeechAgent gRPC TLS artifacts (server.p12 + client_ca.pem)

Option A) Generate via Orchestrator API (recommended when DFIR server is running):

```bash
curl -sS -X POST "https://dfir.skplanet.com:443/v1/leechagent/host-01/grpc-tls" \
  -H "X-IR-Key: dev" \
  --cacert /data/ir/pki/ca.crt.pem \
  --cert /data/ir/mtls/host-01/client.crt.pem \
  --key  /data/ir/mtls/host-01/client.key.pem \
  -d '{}' | jq .
```

This returns:
- `server_p12_b64` + `p12_password`
- `client_ca_pem`
- also saves files under `/data/ir/leechagent_tls/<host>/`

Option B) Generate offline with the helper script (same output):

```bash
python3 /work/ir/scripts/gen_leechagent_grpc_tls.py \
  --pki-dir /data/ir/pki \
  --out-dir /data/ir/leechagent_tls \
  --host "win-test-01" \
  --ip "10.10.10.10" \
  --p12-pass "CHANGE_ME_STRONG"
```

Copy to the Windows PC (same folder as `leechagent.exe` + `libleechgrpc.dll`):
- `server.p12`
- `client_ca.pem`

