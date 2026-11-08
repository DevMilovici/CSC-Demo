"""Demo PKI for the toy RSSP.

In a real remote signing service the private keys live inside an HSM / QSCD and
the certificates are issued by a separate certificate authority. Here both are
simulated in software so the demo runs anywhere:

* a self-signed "CSC Demo Root CA"
* one RSA-2048 key + end-entity certificate per credential

Everything is persisted under server/data/ (or $CSC_DATA_DIR) so the client can trust the same
root CA across restarts. NEVER use this for real signatures.
"""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

DATA_DIR = Path(os.environ.get("CSC_DATA_DIR") or Path(__file__).resolve().parent / "data")
CA_KEY = DATA_DIR / "demo-root-ca.key.pem"
CA_CERT = DATA_DIR / "demo-root-ca.pem"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write_key(path: Path, key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def _read_key(path: Path) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_or_create_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if CA_KEY.exists() and CA_CERT.exists():
        return _read_key(CA_KEY), x509.load_pem_x509_certificate(CA_CERT.read_bytes())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSC Demo Trust Services"),
            x509.NameAttribute(NameOID.COMMON_NAME, "CSC Demo Root CA"),
        ]
    )
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .sign(key, hashes.SHA256())
    )
    _write_key(CA_KEY, key)
    CA_CERT.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def _issue(
    key: rsa.RSAPrivateKey,
    subject: x509.Name,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    policy_oid: str | None = None,
) -> x509.Certificate:
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # a.k.a. nonRepudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    if policy_oid:
        builder = builder.add_extension(
            x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier(policy_oid), None)]),
            critical=False,
        )
    return builder.sign(ca_key, hashes.SHA256())


def _save(credential_id: str, key: rsa.RSAPrivateKey, cert: x509.Certificate) -> None:
    _write_key(DATA_DIR / f"{credential_id}.key.pem", key)
    (DATA_DIR / f"{credential_id}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_or_create_credential(
    credential_id: str,
    common_name: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Return (private key, end-entity certificate) for a built-in demo credential."""
    key_path = DATA_DIR / f"{credential_id}.key.pem"
    cert_path = DATA_DIR / f"{credential_id}.pem"
    if key_path.exists() and cert_path.exists():
        return _read_key(key_path), x509.load_pem_x509_certificate(cert_path.read_bytes())

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSC Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    cert = _issue(key, subject, ca_key, ca_cert)
    _save(credential_id, key, cert)
    return key, cert


def issue_credential(
    credential_id: str,
    given_name: str,
    family_name: str,
    policy_oid: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Generate a fresh key pair and certificate for credentials/create.

    The subject comes from the verified account data, never from the client.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CSC Demo"),
            x509.NameAttribute(NameOID.GIVEN_NAME, given_name),
            x509.NameAttribute(NameOID.SURNAME, family_name),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{given_name} {family_name}"),
        ]
    )
    cert = _issue(key, subject, ca_key, ca_cert, policy_oid)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _save(credential_id, key, cert)
    return key, cert
