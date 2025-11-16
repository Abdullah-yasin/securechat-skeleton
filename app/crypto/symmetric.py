from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

_BLOCK_SIZE = 16  # AES block size in bytes (128 bits)

def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypts the plaintext using AES-128 in CBC mode with PKCS7 padding.
    Returns a tuple (iv, ciphertext), both as raw bytes.
    """
    if len(key) != _BLOCK_SIZE:
        raise ValueError("AES key must be 16 bytes (128-bit)")

    iv = os.urandom(_BLOCK_SIZE)

    padder = padding.PKCS7(_BLOCK_SIZE * 8).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv, ciphertext

def decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts the ciphertext using AES-128 in CBC mode and removes PKCS7 padding.
    Returns the original plaintext bytes.
    """
    if len(key) != _BLOCK_SIZE:
        raise ValueError("AES key must be 16 bytes (128-bit)")
    if len(iv) != _BLOCK_SIZE:
        raise ValueError("AES CBC IV must be 16 bytes")

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(_BLOCK_SIZE * 8).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext

def encrypt_text(key: bytes, text: str) -> tuple[bytes, bytes]:
    """
    Convenience wrapper: encrypts a UTF-8 string.
    Returns (iv, ciphertext).
    """
    return encrypt_aes_cbc(key, text.encode('utf-8'))

def decrypt_text(key: bytes, iv: bytes, ciphertext: bytes) -> str:
    """
    Convenience wrapper: decrypts and decodes UTF-8 string.
    """
    plaintext = decrypt_aes_cbc(key, iv, ciphertext)
    return plaintext.decode('utf-8')

