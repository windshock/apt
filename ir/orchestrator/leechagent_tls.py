from __future__ import annotations

import base64
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class LeechAgentBundle:
    host: str
    ip: str | None
    p12_password: str
    server_p12: bytes
    client_ca_pem: bytes
    server_crt_pem: bytes

    def server_p12_b64(self) -> str:
        return base64.b64encode(self.server_p12).decode("ascii")

    def client_ca_pem_str(self) -> str:
        return self.client_ca_pem.decode("utf-8")

    def server_crt_pem_str(self) -> str:
        return self.server_crt_pem.decode("utf-8")


class LeechAgentTLSIssuer:
    """
    Issues a server TLS bundle for Windows LeechAgent gRPC.

    Output:
    - server.p12 (server cert + key + CA chain)
    - client_ca.pem (CA cert that LeechAgent trusts for mTLS client auth)
    """

    def __init__(self, *, pki_dir: Path, out_dir: Path):
        self.pki_dir = pki_dir
        self.out_dir = out_dir
        self.pki_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    def _ca_paths(self) -> tuple[Path, Path]:
        return self.pki_dir / "ca.key.pem", self.pki_dir / "ca.crt.pem"

    def _load_ca(self) -> tuple[object, x509.Certificate, bytes]:
        ca_key_path, ca_crt_path = self._ca_paths()
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_crt_pem = ca_crt_path.read_bytes()
        ca_crt = x509.load_pem_x509_certificate(ca_crt_pem)
        return ca_key, ca_crt, ca_crt_pem

    def issue(
        self,
        *,
        host: str,
        ip: str | None,
        p12_password: str | None = None,
        days: int = 365,
        write_files: bool = True,
    ) -> LeechAgentBundle:
        ca_key, ca_crt, ca_crt_pem = self._load_ca()

        key = ec.generate_private_key(ec.SECP256R1())
        now = _utc_now()
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])

        san_entries: list[x509.GeneralName] = [x509.DNSName(host)]
        if ip:
            # best effort: if it's not an IP, ignore
            try:
                import ipaddress

                san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except Exception:
                pass

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_crt.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(private_key=ca_key, algorithm=hashes.SHA256())
        )

        pwd = p12_password or secrets.token_urlsafe(18)
        server_p12 = pkcs12.serialize_key_and_certificates(
            name=b"leechagent-grpc",
            key=key,
            cert=cert,
            cas=[ca_crt],
            encryption_algorithm=serialization.BestAvailableEncryption(pwd.encode("utf-8")),
        )

        bundle_dir = self.out_dir / host
        if write_files:
            bundle_dir.mkdir(parents=True, exist_ok=True)
            (bundle_dir / "server.p12").write_bytes(server_p12)
            (bundle_dir / "client_ca.pem").write_bytes(ca_crt_pem)
            (bundle_dir / "server.crt.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

        return LeechAgentBundle(
            host=host,
            ip=ip,
            p12_password=pwd,
            server_p12=server_p12,
            client_ca_pem=ca_crt_pem,
            server_crt_pem=cert.public_bytes(serialization.Encoding.PEM),
        )

