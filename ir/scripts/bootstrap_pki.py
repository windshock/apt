from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_ca(pki_dir: Path) -> tuple[Path, Path]:
    ca_key = pki_dir / "ca.key.pem"
    ca_crt = pki_dir / "ca.crt.pem"
    if ca_key.exists() and ca_crt.exists():
        return ca_key, ca_crt

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "DFIR IR Internal CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "skplanet"),
        ]
    )
    now = utc_now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    ca_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    ca_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return ca_key, ca_crt


def ensure_server_cert(pki_dir: Path, hosts: list[str]) -> tuple[Path, Path]:
    server_key = pki_dir / "server.key.pem"
    server_crt = pki_dir / "server.crt.pem"
    if server_key.exists() and server_crt.exists():
        return server_key, server_crt

    ca_key_path, ca_crt_path = ensure_ca(pki_dir)
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_crt = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())

    key = ec.generate_private_key(ec.SECP256R1())
    now = utc_now()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0] if hosts else "dfir.skplanet.com")])

    san = x509.SubjectAlternativeName([x509.DNSName(h) for h in hosts])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_crt.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(san, critical=False)
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

    server_key.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    server_crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return server_key, server_crt


def main() -> int:
    ap = argparse.ArgumentParser(description="Bootstrap IR PKI (CA + server cert) into /data/ir/pki.")
    ap.add_argument("--pki-dir", default="/data/ir/pki")
    ap.add_argument("--hosts", default="dfir.skplanet.com,localhost,ir-gateway")
    args = ap.parse_args()

    pki_dir = Path(args.pki_dir)
    pki_dir.mkdir(parents=True, exist_ok=True)
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]

    ensure_ca(pki_dir)
    ensure_server_cert(pki_dir, hosts=hosts)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

