import os
import pymysql
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


def get_connection():
    """
    Return a new PyMySQL connection using environment variables.

    Required env vars:
      DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME
    """
    host = os.getenv("DB_HOST", "localhost")
    port = int(os.getenv("DB_PORT", "3306"))
    user = os.getenv("DB_USER", "root")
    password = os.getenv("DB_PASSWORD", "")
    db_name = os.getenv("DB_NAME", "securechat")

    return pymysql.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )

# ---------- Classic (mod-p) Diffie–Hellman for CHAT SESSION ----------

import hashlib

# A standard 2048-bit MODP group prime (RFC 3526 group 14)
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
    shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, "big")
    h = hashlib.sha256(shared_bytes).digest()
    return h[:16]
