"""Simple TCP server with certificate handshake (no TLS yet)."""

from app.crypto import dh, symmetric
import base64

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
    # Receive until newline
    buffer = b""
    while not buffer.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk
    if not buffer:
        raise ConnectionError("No data received from client")
    return json.loads(buffer.decode("utf-8"))


def load_certificate_bytes(cert_bytes: bytes) -> x509.Certificate:
    """Load an X.509 certificate directly from PEM bytes."""
    return x509.load_pem_x509_certificate(cert_bytes)


def main():
    # Load keys/certs
    # (server_key not used yet, but we’ll need it later for signatures)
    server_key = load_private_key("certs/server.key")
    server_cert = load_certificate("certs/server.crt")
    ca_cert = load_ca_certificate()

    # Prepare server PEM as text
    server_cert_pem = server_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")

    HOST, PORT = "127.0.0.1", 9000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(1)
        print(f"Server listening on {HOST}:{PORT}")
        conn, addr = srv.accept()
        with conn:
            print(f"Accepted connection from {addr}")

            try:
                # 1. Receive client_hello with PEM cert
                msg = recv_json(conn)
                if not (
                    isinstance(msg, dict)
                    and msg.get("type") == "client_hello"
                    and "cert" in msg
                ):
                    raise ValueError("Invalid client_hello message format")

                client_cert_pem = msg["cert"]
                client_cert = load_certificate_bytes(client_cert_pem.encode("utf-8"))

                # 2. Verify client cert using CA and expected CN
                verify_peer_certificate(
                    peer_cert=client_cert,
                    ca_cert=ca_cert,
                    expected_cn="SecureChatClient",
                )

                print("Client certificate validated successfully; sending server_hello.")

                # 3. Send server_hello with server PEM cert
                send_json(
                    conn,
                    {
                        "type": "server_hello",
                        "cert": server_cert_pem,
                    },
                )

                # ---- Ephemeral Diffie–Hellman key exchange ----
                import base64
                from app.crypto import dh

                # 1) Receive client's DH public key
                dh_msg = recv_json(conn)
                if not (
                    isinstance(dh_msg, dict)
                    and dh_msg.get("type") == "dh_client_key"
                    and "pub" in dh_msg
                ):
                    raise ValueError("Invalid dh_client_key message format")

                client_pub_b64 = dh_msg["pub"]
                try:
                    client_pub_bytes = base64.b64decode(client_pub_b64)
                except Exception:
                    raise ValueError("Failed to base64-decode client DH public key")

                # 2) Generate ephemeral keypair
                srv_priv, srv_pub = dh.generate_keypair()

                # 3) Compute shared secret
                shared = dh.derive_shared_secret(srv_priv, client_pub_bytes)

                # 4) Derive 16-byte AES session key
                session_key = dh.derive_aes_key_from_shared(shared)

                # 5) Send back server's DH public key (base64-encoded)
                srv_pub_b64 = base64.b64encode(srv_pub).decode("ascii")
                send_json(
                    conn,
                    {
                        "type": "dh_server_key",
                        "pub": srv_pub_b64,
                    }
                )

                # 6) Print session key info
                print(f"Server derived session key of length {len(session_key)} bytes")

                # Connection remains open for further protocol
                print("Handshake complete, ready for next phase.")

            except ValueError as ve:
                print(f"CERT ERROR: {ve}")
                try:
                    send_json(conn, {"type": "error", "message": str(ve)})
                except Exception:
                    pass  # ignore send error
            except Exception as e:
                print(f"Fatal server error: {e}")


if __name__ == "__main__":
    main()
