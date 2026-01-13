from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def main() -> int:
    ap = argparse.ArgumentParser(description="Bootstrap a worker mTLS client cert signed by IR internal CA.")
    ap.add_argument("--pki-dir", default="/data/ir/pki")
    ap.add_argument("--out-dir", default="/data/ir/mtls/host-01", help="Directory to write client.key.pem/client.crt.pem")
    ap.add_argument("--cn", default="host-01", help="Client certificate CN")
    ap.add_argument("--days", type=int, default=365)
    args = ap.parse_args()

    pki_dir = Path(args.pki_dir)
    ca_key_path = pki_dir / "ca.key.pem"
    ca_crt_path = pki_dir / "ca.crt.pem"
    if not ca_key_path.exists() or not ca_crt_path.exists():
        raise SystemExit(f"missing CA under {pki_dir} (expected ca.key.pem and ca.crt.pem)")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / "client.key.pem"
    crt_path = out_dir / "client.crt.pem"

    if key_path.exists() and crt_path.exists():
        return 0

    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_crt = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())

    key = ec.generate_private_key(ec.SECP256R1())
    now = _utc_now()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, str(args.cn))])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_crt.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=int(args.days)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
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

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

