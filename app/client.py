"""Simple TCP client for certificate handshake (no TLS yet)."""

import socket
import json
import base64

from cryptography.hazmat.primitives import serialization
from cryptography import x509

from app.crypto.pki import (
    load_private_key,
    load_certificate,
    load_ca_certificate,
    verify_peer_certificate,
)
from app.crypto import dh, symmetric
from app.common.secure_channel import encrypt_envelope, decrypt_envelope


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
    client_key = load_private_key("certs/client.key")  # reserved for later
    client_cert = load_certificate("certs/client.crt")
    ca_cert = load_ca_certificate()

    # PEM encoding of our own cert to send
    client_cert_pem = client_cert.public_bytes(
        encoding=serialization.Encoding.PEM
    ).decode("utf-8")

    HOST, PORT = "127.0.0.1", 9000

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        # ---------- Certificate handshake ----------
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
            return  # Abort on failed handshake

        # ---------- Ephemeral X25519 DH + encrypted register/login ----------
        try:
            # 1) Generate an ephemeral keypair
            cli_priv, cli_pub = dh.generate_keypair()

            # 2) Send JSON to the server with our public key (base64-encoded)
            cli_pub_b64 = base64.b64encode(cli_pub).decode("ascii")
            send_json(
                sock,
                {
                    "type": "dh_client_key",
                    "pub": cli_pub_b64,
                }
            )

            # 3) Receive server's DH public key in JSON
            dh_msg = recv_json(sock)
            if not (
                isinstance(dh_msg, dict)
                and dh_msg.get("type") == "dh_server_key"
                and "pub" in dh_msg
            ):
                raise ValueError("Invalid dh_server_key message format")

            srv_pub_b64 = dh_msg["pub"]

            # 4) Decode the server pubkey from base64
            try:
                srv_pub_bytes = base64.b64decode(srv_pub_b64)
            except Exception:
                raise ValueError("Failed to base64-decode server DH public key")

            # 5) Compute the shared secret
            shared = dh.derive_shared_secret(cli_priv, srv_pub_bytes)

            # 6) Derive the 16-byte AES session key
            session_key = dh.derive_aes_key_from_shared(shared)
            print(f"Client derived session key of length {len(session_key)} bytes")

            # 7) Ask user for action
            mode = input("Action (register/login): ").strip().lower()
            if mode not in ("register", "login"):
                print("Error: Action must be 'register' or 'login'")
                return

            # 8) Prompt for credentials
            username = input("Username: ")
            password = input("Password: ")

            # 9) Build payload
            payload = {
                "kind": mode,
                "username": username,
                "password": password,
            }

            # 10) Encrypt and send
            env = encrypt_envelope(session_key, payload)
            send_json(sock, env)

            # 11) Receive and decrypt response
            resp_env = recv_json(sock)
            resp_payload = decrypt_envelope(session_key, resp_env)

            # 12) Print server response
            print("Server response:", resp_payload)

            # ---------- If login successful, start chat-session DH ----------
            if mode == "login" and resp_payload.get("status") == "ok":
                # 1) Receive server's chat DH params + A, encrypted with control session_key
                dh_env = recv_json(sock)
                dh_payload = decrypt_envelope(session_key, dh_env)

                if dh_payload.get("kind") != "chat_dh_params":
                    print("Unexpected payload instead of chat_dh_params:", dh_payload)
                    return

                p = int(dh_payload["p"])
                g = int(dh_payload["g"])
                A = int(dh_payload["A"])

                # 2) Generate client's classic DH keypair
                cli_priv_chat, cli_pub_chat = dh.classic_generate_keypair()

                # 3) Derive shared secret and chat AES key
                shared_int = dh.classic_derive_shared(cli_priv_chat, A)
                chat_key = dh.classic_derive_aes_key_from_shared(shared_int)
                print(f"Client chat key length: {len(chat_key)} bytes")

                # 4) Send B back to server under control session_key
                chat_resp = {
                    "kind": "chat_dh_response",
                    "B": str(cli_pub_chat),
                }
                resp_env2 = encrypt_envelope(session_key, chat_resp)
                send_json(sock, resp_env2)

                # 5) Ask user for a chat message, encrypt with chat_key, send
                text = input("Enter chat message to send: ")
                chat_msg = {"type": "chat_msg", "text": text}
                chat_env = encrypt_envelope(chat_key, chat_msg)
                send_json(sock, chat_env)

                # 6) Receive encrypted ACK under chat_key
                ack_env = recv_json(sock)
                ack_payload = decrypt_envelope(chat_key, ack_env)
                print("Server chat ACK:", ack_payload)

        except Exception as e:
            print(f"Client error during DH or secure exchange: {e}")


if __name__ == "__main__":
    main()
