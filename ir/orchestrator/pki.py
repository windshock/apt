from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class PKIPaths:
    base: Path
    ca_key: Path
    ca_cert: Path

    @staticmethod
    def under(base: Path) -> "PKIPaths":
        return PKIPaths(
            base=base,
            ca_key=base / "ca.key.pem",
            ca_cert=base / "ca.crt.pem",
        )


class SimpleCA:
    """
    MVP internal CA for signing client certs from CSRs.
    In production you likely replace this with enterprise PKI.
    """

    def __init__(self, paths: PKIPaths):
        self.paths = paths
        self.paths.base.mkdir(parents=True, exist_ok=True)

    def ensure_ca(self) -> None:
        if self.paths.ca_key.exists() and self.paths.ca_cert.exists():
            return

        # ECDSA P-256 CA key
        ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, "DFIR IR Internal CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "skplanet"),
            ]
        )
        now = _utc_now()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(key_cert_sign=True, crl_sign=True, digital_signature=True,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, content_commitment=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(private_key=ca_key, algorithm=hashes.SHA256())
        )

        self.paths.ca_key.write_bytes(
            ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.paths.ca_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def ca_pem(self) -> bytes:
        return self.paths.ca_cert.read_bytes()

    def sign_csr(self, csr_pem: bytes, *, days: int = 90) -> bytes:
        ca_key = serialization.load_pem_private_key(self.paths.ca_key.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(self.paths.ca_cert.read_bytes())
        csr = x509.load_pem_x509_csr(csr_pem)

        if not csr.is_signature_valid:
            raise ValueError("invalid CSR signature")

        now = _utc_now()
        builder = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=days))
        )

        # copy SAN if present
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            builder = builder.add_extension(san.value, critical=False)
        except x509.ExtensionNotFound:
            pass

        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        builder = builder.add_extension(
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

        cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
        return cert.public_bytes(serialization.Encoding.PEM)

