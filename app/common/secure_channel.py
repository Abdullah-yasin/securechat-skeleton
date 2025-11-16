from app.crypto import symmetric
import base64
import json

def encrypt_envelope(session_key: bytes, payload: dict) -> dict:
    try:
        plaintext_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    except Exception as e:
        raise ValueError(f"Payload serialization failed: {e}")
    iv, ciphertext = symmetric.encrypt_aes_cbc(session_key, plaintext_bytes)
    envelope = {
        "type": "encrypted",
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return envelope

def decrypt_envelope(session_key: bytes, envelope: dict) -> dict:
    if not isinstance(envelope, dict):
        raise ValueError("Envelope must be a dict")
    if envelope.get("type") != "encrypted":
        raise ValueError('Envelope "type" must be "encrypted"')
    if "iv" not in envelope or "ciphertext" not in envelope:
        raise ValueError('Envelope must contain "iv" and "ciphertext" fields')
    try:
        iv = base64.b64decode(envelope["iv"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
    except Exception as e:
        raise ValueError(f"Base64 decoding failed: {e}")
    try:
        plaintext_bytes = symmetric.decrypt_aes_cbc(session_key, iv, ciphertext)
        payload = json.loads(plaintext_bytes.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("Decrypted payload is not a dict")
        return payload
    except Exception as e:
        raise ValueError(f"Decryption or parsing failed: {e}")
