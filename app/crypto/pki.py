"""
PKI helpers for secure chat.

- Load private keys and certificates from disk.
- Verify a peer certificate against our CA and expected CN.
"""

import os
from pathlib import Path
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID


# ---------- path helpers ----------

def _project_root() -> Path:
    # This file is app/crypto/pki.py -> go up two levels to project root
    return Path(__file__).resolve().parents[2]


def _abs_path(rel_path: str) -> Path:
    return _project_root() / rel_path


# ---------- load helpers ----------

def load_private_key(path: str):
    """Load an unencrypted PEM RSA private key from a relative path."""
    full = _abs_path(path)
    with open(full, "rb") as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)


def load_certificate(path: str) -> x509.Certificate:
    """Load a PEM X.509 certificate from a relative path."""
    full = _abs_path(path)
    with open(full, "rb") as f:
        data = f.read()
    return x509.load_pem_x509_certificate(data)


def load_ca_certificate() -> x509.Certificate:
    """Load the root CA certificate (certs/ca.crt)."""
    return load_certificate("certs/ca.crt")


# ---------- verification ----------

def verify_peer_certificate(
    peer_cert: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: str,
) -> None:
    """
    Verify that:
    - peer_cert is issued by ca_cert (signature + issuer check)
    - peer_cert is currently valid (time window)
    - CN(subject) == expected_cn

    Raises ValueError("BAD CERT: ...") on any failure.
    """

    # 1. Check CN
    try:
        cn_attr = peer_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        cn_value = cn_attr.value
    except Exception:
        raise ValueError("BAD CERT: certificate has no Common Name")

    if cn_value != expected_cn:
        raise ValueError(f"BAD CERT: CN mismatch (got {cn_value!r}, expected {expected_cn!r})")

    # 2. Check validity period (time)
    now = datetime.now(timezone.utc)

    # cryptography's datetimes are naive; attach UTC before comparison
    not_before = peer_cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = peer_cert.not_valid_after.replace(tzinfo=timezone.utc)

    if now < not_before:
        raise ValueError("BAD CERT: certificate not yet valid")
    if now > not_after:
        raise ValueError("BAD CERT: certificate expired")

    # 3. Check issuer matches CA subject
    if peer_cert.issuer != ca_cert.subject:
        raise ValueError("BAD CERT: issuer does not match CA subject")

    # 4. Verify signature using CA public key
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            signature=peer_cert.signature,
            data=peer_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=peer_cert.signature_hash_algorithm,
        )
    except Exception as e:
        raise ValueError(f"BAD CERT: signature verification failed ({e})")
