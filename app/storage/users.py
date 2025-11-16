"""
User storage backed by MySQL.
"""

from typing import Optional, Tuple

from .db import get_connection


def create_user(username: str, salt_hex: str, hash_hex: str) -> bool:
    """
    Insert a new user. Returns True if inserted, False if username exists.
    """
    sql = """
        INSERT INTO users (username, salt, pwdhash)
        VALUES (%s, UNHEX(%s), %s)
    """
    try:
        conn = get_connection()
        with conn.cursor() as cur:
            cur.execute(sql, (username, salt_hex, hash_hex))
        conn.close()
        return True
    except Exception as e:
        # Likely duplicate username or DB error
        # You can inspect/log e if needed
        return False


def get_user(username: str) -> Optional[Tuple[str, str]]:
    """
    Return (salt_hex, hash_hex) for username, or None if not found.
    """
    sql = """
        SELECT HEX(salt) AS salt_hex, pwdhash
        FROM users
        WHERE username = %s
    """
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (username,))
            row = cur.fetchone()
        conn.close()
        if not row:
            return None
        return row["salt_hex"], row["pwdhash"]
    finally:
        try:
            conn.close()
        except Exception:
            pass
