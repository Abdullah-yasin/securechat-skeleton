"""Simple TCP client for certificate handshake (no TLS yet)."""

import socket
import json

from cryptography.hazmat.primitives import serialization
from cryptography import x509

from app.crypto.pki import (
    load_private_key,
    load_certificate,
    load_ca_certificate,
    verify_peer_certificate,
)


def send_json(sock, obj):
    data = json.dumps(obj).encode("utf-8") + b"\n"
    sock.sendall(data)


def recv_json(sock):
    buffer = b""
    while not buffer.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
    if not buffer:
        raise ConnectionError("No data received from server")
    return json.loads(buffer.decode("utf-8"))


def load_certificate_bytes(cert_bytes: bytes) -> x509.Certificate:
    """Load an X.509 certificate directly from PEM bytes."""
    return x509.load_pem_x509_certificate(cert_bytes)


def main():
    # Load keys/certs
    # (client_key not used yet, but will be needed for signatures later)
    client_key = load_private_key("certs/client.key")
    client_cert = load_certificate("certs/client.crt")
    ca_cert = load_ca_certificate()

    # PEM encoding of our own cert to send
    client_cert_pem = client_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")

    HOST, PORT = "127.0.0.1", 9000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        try:
            # 1. Send client_hello with client cert PEM
            send_json(
                sock,
                {
                    "type": "client_hello",
                    "cert": client_cert_pem,
                },
            )

            # 2. Receive server_hello with server cert PEM
            msg = recv_json(sock)
            if not (
                isinstance(msg, dict)
                and msg.get("type") == "server_hello"
                and "cert" in msg
            ):
                raise ValueError("Invalid server_hello message format")

            server_cert_pem = msg["cert"]
            server_cert = load_certificate_bytes(server_cert_pem.encode("utf-8"))

            # 3. Verify server certificate via CA and expected CN
            verify_peer_certificate(
                peer_cert=server_cert,
                ca_cert=ca_cert,
                expected_cn="SecureChatServer",
            )

            print("Server certificate validated successfully; handshake complete.")

        except Exception as e:
            print(f"Handshake failed: {e}")


if __name__ == "__main__":
    main()
