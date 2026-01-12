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

