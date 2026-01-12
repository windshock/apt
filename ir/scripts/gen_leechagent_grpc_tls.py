from __future__ import annotations

import argparse
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class CAPaths:
    ca_key: Path
    ca_crt: Path


def ensure_ca(pki_dir: Path) -> CAPaths:
    pki_dir.mkdir(parents=True, exist_ok=True)
    ca_key = pki_dir / "ca.key.pem"
    ca_crt = pki_dir / "ca.crt.pem"
    if ca_key.exists() and ca_crt.exists():
        return CAPaths(ca_key=ca_key, ca_crt=ca_crt)

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
    return CAPaths(ca_key=ca_key, ca_crt=ca_crt)


def gen_server_cert(
    *,
    ca_key_pem: bytes,
    ca_crt_pem: bytes,
    common_name: str,
    dns_sans: list[str],
    ip_sans: list[str],
    days: int,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    ca_crt = x509.load_pem_x509_certificate(ca_crt_pem)

    key = ec.generate_private_key(ec.SECP256R1())
    now = utc_now()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    san_entries: list[x509.GeneralName] = []
    for d in dns_sans:
        san_entries.append(x509.DNSName(d))
    for ip in ip_sans:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_crt.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
    )
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return key, cert


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate LeechAgent gRPC TLS artifacts (server.p12 + client_ca.pem).")
    ap.add_argument("--pki-dir", default="/data/ir/pki", help="CA location (ca.key.pem/ca.crt.pem)")
    ap.add_argument("--out-dir", default="/data/ir/leechagent_tls", help="Output directory")
    ap.add_argument("--host", required=True, help="Windows host DNS/FQDN for certificate CN/SAN")
    ap.add_argument("--ip", default="", help="Windows endpoint IP for SAN (optional)")
    ap.add_argument("--p12-pass", required=True, help="Password for server.p12")
    ap.add_argument("--days", type=int, default=365, help="Server cert validity (days)")
    args = ap.parse_args()

    pki_dir = Path(args.pki_dir)
    out_dir = Path(args.out_dir) / args.host
    out_dir.mkdir(parents=True, exist_ok=True)

    ca = ensure_ca(pki_dir)
    ca_key_pem = ca.ca_key.read_bytes()
    ca_crt_pem = ca.ca_crt.read_bytes()

    dns_sans = [args.host]
    ip_sans = [args.ip] if args.ip.strip() else []

    key, cert = gen_server_cert(
        ca_key_pem=ca_key_pem,
        ca_crt_pem=ca_crt_pem,
        common_name=args.host,
        dns_sans=dns_sans,
        ip_sans=ip_sans,
        days=args.days,
    )

    # Write outputs
    (out_dir / "client_ca.pem").write_bytes(ca_crt_pem)
    (out_dir / "server.crt.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (out_dir / "server.key.pem").write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    p12 = pkcs12.serialize_key_and_certificates(
        name=b"leechagent-grpc",
        key=key,
        cert=cert,
        cas=[x509.load_pem_x509_certificate(ca_crt_pem)],
        encryption_algorithm=serialization.BestAvailableEncryption(args.p12_pass.encode("utf-8")),
    )
    (out_dir / "server.p12").write_bytes(p12)

    print(f"OK: {out_dir}")
    print("Files:")
    print(f"- {out_dir / 'server.p12'}")
    print(f"- {out_dir / 'client_ca.pem'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

