"""RSA PKCS#1 v1.5 SHA-256 sign/verify helpers.

These helpers assume you already have an RSA private key object
(e.g. loaded via app.crypto.pki.load_private_key) and you want to
sign / verify bytes or JSON objects.
"""

from __future__ import annotations

from typing import Any, Dict
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature


def sign_bytes(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
    """
    Sign raw bytes with RSA PKCS#1 v1.5 + SHA-256.

    Returns the signature as raw bytes.
    """
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return signature


def verify_bytes(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
    """
    Verify a PKCS#1 v1.5 + SHA-256 signature over raw bytes.

    Returns True if the signature is valid, False otherwise.
    """
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def _canonical_json(obj: Dict[str, Any]) -> bytes:
    """
    Convert a dict to canonical JSON bytes (sorted keys, no extra spaces).

    This ensures the same JSON always hashes/signs to the same value.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_json(private_key: rsa.RSAPrivateKey, obj: Dict[str, Any]) -> bytes:
    """
    Sign a JSON-serializable dict using canonical JSON encoding.

    Returns the signature bytes.
    """
    data = _canonical_json(obj)
    return sign_bytes(private_key, data)


def verify_json(public_key: rsa.RSAPublicKey, obj: Dict[str, Any], signature: bytes) -> bool:
    """
    Verify a signature produced by sign_json() for the given object.
    """
    data = _canonical_json(obj)
    return verify_bytes(public_key, data, signature)
