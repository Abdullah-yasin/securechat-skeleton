from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import hashlib


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an X25519 keypair and return (private_bytes, public_bytes).
    Both are raw 32-byte sequences suitable for sending over the network.
    """
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()

    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )

    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return priv_bytes, pub_bytes


def derive_shared_secret(private_key_bytes: bytes, peer_public_bytes: bytes) -> bytes:
    priv = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)
    peer_pub = x25519.X25519PublicKey.from_public_bytes(peer_public_bytes)
    return priv.exchange(peer_pub)


def derive_aes_key_from_shared(shared_secret: bytes) -> bytes:
    digest = hashlib.sha256(shared_secret).digest()
    return digest[:16]  # AES-128

# ---------- Classic (mod-p) Diffie–Hellman for CHAT SESSION ----------

import os

# A standard 2048-bit MODP group prime (RFC 3526 group 14, shortened)
CLASSIC_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
    16,
)
CLASSIC_G = 2


def classic_generate_keypair():
    """
    Return (priv, pub) for classic DH using global CLASSIC_P, CLASSIC_G.
    priv is a random 256-bit integer.
    pub = g^priv mod p
    """
    priv = int.from_bytes(os.urandom(32), "big")
    pub = pow(CLASSIC_G, priv, CLASSIC_P)
    return priv, pub


def classic_derive_shared(priv: int, peer_pub: int) -> int:
    """
    Compute shared secret S = peer_pub^priv mod p.
    """
    return pow(peer_pub, priv, CLASSIC_P)


def classic_derive_aes_key_from_shared(shared_int: int) -> bytes:
    """
    Derive a 16-byte AES key from the integer shared secret using SHA-256,
    taking the first 16 bytes.
    """
    # convert integer to bytes (big-endian)
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    h = hashlib.sha256(shared_bytes).digest()
    return h[:16]
