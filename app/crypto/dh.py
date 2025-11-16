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
