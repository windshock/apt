from __future__ import annotations

import argparse
import json
import os
import socket
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
        r = requests.get(
            enroll_url.rstrip("/") + "/v1/pki/ca.crt.pem",
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
    # If IR_TLS_CA is already set (e.g., to a public/enterprise CA bundle for gateway TLS),
    # do not override it during enrollment. The CA returned by enrollment is the internal CA
    # used to *issue client certs*, not necessarily the CA used to verify the gateway's
    # server certificate.
    existing_verify_ca = os.getenv("IR_TLS_CA")

    if os.path.exists(key_path) and os.path.exists(cert_path) and os.path.exists(ca_path):
        # Ensure current process uses existing material.
        os.environ["IR_TLS_CERT"] = cert_path
        os.environ["IR_TLS_KEY"] = key_path
        if not existing_verify_ca:
            os.environ["IR_TLS_CA"] = ca_path
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
    if not existing_verify_ca:
        os.environ["IR_TLS_CA"] = ca_path

    return {"key": key_path, "cert": cert_path, "ca": ca_path}


def main() -> int:
    ap = argparse.ArgumentParser(description="IR Agent (MVP stub): check isolation and join orchestrator.")
    ap.add_argument("--agent-id", default=os.getenv("IR_AGENT_ID", socket.gethostname()))
    ap.add_argument("--hostname", default=os.getenv("IR_AGENT_HOSTNAME", socket.gethostname()))
    ap.add_argument("--orch-url", default=os.getenv("IR_ORCH_URL", "http://ir-orchestrator:8080"))
    ap.add_argument("--shared-key", default=os.getenv("IR_SHARED_KEY", "dev"))
    ap.add_argument("--require-signature", action="store_true", default=os.getenv("IR_REQUIRE_SIGNATURE", "0") == "1")
    ap.add_argument("--internet-probe", default=os.getenv("IR_INTERNET_PROBE", "https://example.com"))
    ap.add_argument("--assume-isolated", action="store_true", help="Bypass isolation checks (demo/testing).")
    ap.add_argument("--poll-seconds", type=int, default=30)
    ap.add_argument("--startup-wait-seconds", type=int, default=30)
    ap.add_argument("--enroll-mtls", action="store_true", default=os.getenv("IR_ENROLL_MTLS", "0") == "1")
    ap.add_argument("--mtls-out", default=os.getenv("IR_MTLS_DIR", "/data/ir/mtls"))
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

    payload = {"agent_id": args.agent_id, "hostname": args.hostname, "ip": None, "capabilities": {}}
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

    # In real agent: start LeechAgent here and wait for work order / keep-alive.
    # MVP: just periodic heartbeat (re-join is an upsert).
    while True:
        time.sleep(args.poll_seconds)
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

