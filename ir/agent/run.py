from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
from typing import Any

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ir.common.signing import SignedRequest


def can_reach_orchestrator(url: str, timeout: float = 3.0) -> bool:
    try:
        verify = os.getenv("IR_TLS_CA")
        cert = None
        cert_file = os.getenv("IR_TLS_CERT")
        key_file = os.getenv("IR_TLS_KEY")
        if cert_file and key_file:
            cert = (cert_file, key_file)
        r = requests.get(url.rstrip("/") + "/healthz", timeout=timeout, verify=verify or True, cert=cert)
        return r.status_code == 200
    except Exception:
        return False


def can_reach_enroll(enroll_url: str, shared_key: str, timeout: float = 3.0) -> bool:
    """
    Bootstrap reachability check for enrollment endpoint (no client cert).
    """
    try:
        verify = os.getenv("IR_TLS_CA")
        base = enroll_url.rstrip("/")

        # Prefer unauthenticated bootstrap CA endpoint (served via gateway enroll port).
        r = requests.get(base + "/bootstrap/ca.crt.pem", timeout=timeout, verify=verify or True)
        if r.status_code == 200:
            return True

        # Backward compatible: legacy endpoint requires shared key and returns JSON.
        r = requests.get(
            base + "/v1/pki/ca.crt.pem",
            timeout=timeout,
            verify=verify or True,
            headers={"X-IR-Key": shared_key},
        )
        return r.status_code == 200
    except Exception:
        return False


def internet_is_blocked(probe_url: str, timeout: float = 2.0) -> bool:
    """
    Heuristic: if HTTP(S) to public probe fails, treat as "blocked".
    In real deployment, this should be aligned with your isolation policy.
    """
    try:
        r = requests.get(probe_url, timeout=timeout)
        return r.status_code < 200 or r.status_code >= 400
    except Exception:
        return True


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
    return requests.post(url, data=body, headers=headers, timeout=10, verify=verify or True, cert=cert)


def fetch_leechagent_grpc_tls(
    *,
    orch_url: str,
    key: str,
    require_sig: bool,
    agent_id: str,
    hostname: str,
    out_dir: str,
    ip: str | None = None,
) -> dict[str, str]:
    """
    Fetch LeechAgent gRPC TLS artifacts from orchestrator and write them to out_dir:
    - server.p12
    - client_ca.pem
    - leechagent_tls.json (metadata: p12_password, host/ip)
    """
    os.makedirs(out_dir, exist_ok=True)
    path = f"/v1/leechagent/{agent_id}/grpc-tls"
    payload = {"host": hostname, "ip": ip}
    r = post_json(orch_url=orch_url, key=key, require_sig=require_sig, path=path, payload=payload)
    if r.status_code >= 300:
        raise RuntimeError(f"leechagent_tls failed: {r.status_code} {r.text}")
    obj = r.json()

    p12_b64 = obj.get("server_p12_b64") or ""
    client_ca_pem = obj.get("client_ca_pem") or ""
    p12_password = obj.get("p12_password") or ""
    if not p12_b64 or not client_ca_pem or not p12_password:
        raise RuntimeError("leechagent_tls invalid response (missing p12/ca/password)")

    server_p12 = base64.b64decode(p12_b64.encode("ascii"))
    p12_path = os.path.join(out_dir, "server.p12")
    ca_path = os.path.join(out_dir, "client_ca.pem")
    meta_path = os.path.join(out_dir, "leechagent_tls.json")
    with open(p12_path, "wb") as f:
        f.write(server_p12)
    with open(ca_path, "w", encoding="utf-8") as f:
        f.write(client_ca_pem)
    with open(meta_path, "w", encoding="utf-8") as f:
        f.write(json.dumps({"host": obj.get("host"), "ip": obj.get("ip"), "p12_password": p12_password}, ensure_ascii=False, indent=2) + "\n")
    return {"server_p12": p12_path, "client_ca": ca_path, "meta": meta_path}


def maybe_start_leechagent(*, path: str, args: list[str], cwd: str | None) -> subprocess.Popen | None:
    """
    Best-effort spawn of Windows LeechAgent process.
    Operator controls args/cwd.
    """
    if not path:
        return None
    try:
        cmd = [path] + list(args or [])
        return subprocess.Popen(cmd, cwd=cwd or None)
    except Exception as e:
        print(f"leechagent start failed: {type(e).__name__}: {e}", file=sys.stderr)
        return None


def ensure_mtls_cert(
    *,
    orch_url: str,
    shared_key: str,
    require_sig: bool,
    agent_id: str,
    out_dir: str,
    days: int = 90,
) -> dict[str, str]:
    """
    MVP mTLS enrollment:
    - Generate local keypair
    - Create CSR and send to orchestrator for signing
    - Write key/cert/ca to out_dir
    """

    os.makedirs(out_dir, exist_ok=True)
    key_path = os.path.join(out_dir, "client.key.pem")
    cert_path = os.path.join(out_dir, "client.crt.pem")
    ca_path = os.path.join(out_dir, "ca.crt.pem")
    # IMPORTANT:
    # - IR_TLS_CA is used to verify the *gateway/orchestrator server TLS certificate*.
    # - The CA returned by enrollment is the internal CA used to *issue client certs* (for mTLS),
    #   and MUST NOT be forced into IR_TLS_CA, otherwise we break TLS verification when the
    #   gateway uses a public/enterprise cert (e.g., GlobalSign wildcard).
    # Therefore: never mutate IR_TLS_CA here.

    if os.path.exists(key_path) and os.path.exists(cert_path) and os.path.exists(ca_path):
        # Ensure current process uses existing material.
        os.environ["IR_TLS_CERT"] = cert_path
        os.environ["IR_TLS_KEY"] = key_path
        return {"key": key_path, "cert": cert_path, "ca": ca_path}

    key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
        .sign(key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Enrollment may happen on a separate URL (TLS without client cert).
    enroll_url = os.getenv("IR_ENROLL_URL", orch_url)
    # During enrollment, we verify using CA if provided, but do not pass client cert.
    url = enroll_url.rstrip("/") + "/v1/pki/enroll"
    body = json.dumps({"csr_pem": csr_pem, "days": days}, ensure_ascii=False).encode("utf-8")
    headers = _headers(shared_key, "POST", "/v1/pki/enroll", body, require_sig)
    verify = os.getenv("IR_TLS_CA")
    r = requests.post(url, data=body, headers=headers, timeout=10, verify=verify or True)
    if r.status_code >= 300:
        raise RuntimeError(f"enroll failed: {r.status_code} {r.text}")
    obj = r.json()
    cert_pem = obj["cert_pem"]
    ca_pem = obj["ca_pem"]

    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(cert_path, "w", encoding="utf-8") as f:
        f.write(cert_pem)
    with open(ca_path, "w", encoding="utf-8") as f:
        f.write(ca_pem)

    # Export paths for subsequent API calls in this process.
    os.environ["IR_TLS_CERT"] = cert_path
    os.environ["IR_TLS_KEY"] = key_path

    return {"key": key_path, "cert": cert_path, "ca": ca_path}


def main() -> int:
    ap = argparse.ArgumentParser(description="IR Agent (MVP stub): check isolation and join orchestrator.")
    ap.add_argument("--agent-id", default=os.getenv("IR_AGENT_ID", socket.gethostname()))
    ap.add_argument("--hostname", default=os.getenv("IR_AGENT_HOSTNAME", socket.gethostname()))
    ap.add_argument(
        "--ip",
        default=os.getenv("IR_AGENT_IP", ""),
        help="Optional endpoint IP to report to orchestrator (recommended behind gateways/LBs).",
    )
    ap.add_argument("--orch-url", default=os.getenv("IR_ORCH_URL", "http://ir-orchestrator:8080"))
    ap.add_argument("--shared-key", default=os.getenv("IR_SHARED_KEY", "dev"))
    ap.add_argument("--require-signature", action="store_true", default=os.getenv("IR_REQUIRE_SIGNATURE", "0") == "1")
    ap.add_argument("--internet-probe", default=os.getenv("IR_INTERNET_PROBE", "https://example.com"))
    ap.add_argument("--assume-isolated", action="store_true", help="Bypass isolation checks (demo/testing).")
    ap.add_argument("--poll-seconds", type=int, default=30)
    ap.add_argument("--startup-wait-seconds", type=int, default=30)
    ap.add_argument(
        "--run-once",
        action="store_true",
        default=os.getenv("IR_RUN_ONCE", "0") == "1",
        help="Run a single join (and optional TLS fetch / LeechAgent start), then exit. Recommended for Scheduled Task.",
    )
    ap.add_argument("--enroll-mtls", action="store_true", default=os.getenv("IR_ENROLL_MTLS", "0") == "1")
    ap.add_argument("--mtls-out", default=os.getenv("IR_MTLS_DIR", "/data/ir/mtls"))
    ap.add_argument("--fetch-leechagent-tls", action="store_true", default=os.getenv("IR_FETCH_LEECHAGENT_TLS", "0") == "1")
    ap.add_argument("--leechagent-tls-out", default=os.getenv("IR_LEECHAGENT_TLS_OUT", ""))
    ap.add_argument("--leechagent-path", default=os.getenv("IR_LEECHAGENT_PATH", ""))
    ap.add_argument("--leechagent-args", default=os.getenv("IR_LEECHAGENT_ARGS", ""))
    ap.add_argument("--leechagent-cwd", default=os.getenv("IR_LEECHAGENT_CWD", ""))
    args = ap.parse_args()

    deadline = time.time() + max(1, args.startup_wait_seconds)
    orch_ok = False

    # If enrolling and no client cert yet, check bootstrap endpoint instead of mTLS endpoint.
    need_bootstrap = bool(args.enroll_mtls) and not (os.getenv("IR_TLS_CERT") and os.getenv("IR_TLS_KEY"))
    enroll_url = os.getenv("IR_ENROLL_URL", args.orch_url)

    while time.time() < deadline:
        if need_bootstrap:
            orch_ok = can_reach_enroll(enroll_url, args.shared_key)
        else:
            orch_ok = can_reach_orchestrator(args.orch_url)
        if orch_ok:
            break
        time.sleep(1)
    if not orch_ok:
        print("orchestrator unreachable", file=sys.stderr)
        return 2

    isolated = args.assume_isolated or (orch_ok and internet_is_blocked(args.internet_probe))
    if not isolated:
        print("not isolated; exiting (or sleep in real agent)")
        return 0

    if args.enroll_mtls:
        try:
            ensure_mtls_cert(
                orch_url=args.orch_url,
                shared_key=args.shared_key,
                require_sig=bool(args.require_signature),
                agent_id=args.agent_id,
                out_dir=os.path.join(args.mtls_out, args.agent_id),
            )
        except Exception as e:
            print(f"mtls enroll failed: {type(e).__name__}: {e}", file=sys.stderr)
            return 5

    ip_val = (args.ip or "").strip() or None
    payload = {"agent_id": args.agent_id, "hostname": args.hostname, "ip": ip_val, "capabilities": {}}

    if args.fetch_leechagent_tls:
        out_dir = args.leechagent_tls_out or os.path.join(args.mtls_out, args.agent_id, "leechagent_tls")
        try:
            _ = fetch_leechagent_grpc_tls(
                orch_url=args.orch_url,
                key=args.shared_key,
                require_sig=bool(args.require_signature),
                agent_id=args.agent_id,
                hostname=args.hostname,
                ip=None,
                out_dir=out_dir,
            )
        except Exception as e:
            print(f"fetch leechagent tls failed: {type(e).__name__}: {e}", file=sys.stderr)
            return 6

    r = post_json(
        orch_url=args.orch_url,
        key=args.shared_key,
        require_sig=bool(args.require_signature),
        path="/v1/agents/join",
        payload=payload,
    )
    if r.status_code >= 300:
        print(r.text, file=sys.stderr)
        return 3

    leech_proc: subprocess.Popen | None = None
    if args.leechagent_path:
        la_args = [a for a in (args.leechagent_args or "").split() if a.strip()]
        leech_proc = maybe_start_leechagent(path=args.leechagent_path, args=la_args, cwd=(args.leechagent_cwd or None))

    # Scheduled-task friendly mode: do not stay resident.
    # Note: child process (LeechAgent) can keep running after we exit (desired for PoC).
    if args.run_once:
        return 0

    # In real agent: start LeechAgent here and wait for work order / keep-alive.
    # MVP: just periodic heartbeat (re-join is an upsert).
    while True:
        time.sleep(args.poll_seconds)
        if leech_proc is not None:
            try:
                if leech_proc.poll() is not None:
                    print("leechagent exited; stopping agent loop", file=sys.stderr)
                    return 7
            except Exception:
                pass
        r = post_json(
            orch_url=args.orch_url,
            key=args.shared_key,
            require_sig=bool(args.require_signature),
            path="/v1/agents/join",
            payload=payload,
        )
        if r.status_code >= 300:
            print(r.text, file=sys.stderr)
            return 4


if __name__ == "__main__":
    raise SystemExit(main())

