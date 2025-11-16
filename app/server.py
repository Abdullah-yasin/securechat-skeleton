"""Simple TCP server with certificate handshake + DH + encrypted REGISTER/LOGIN."""

import os
import hashlib
import socket
import json
import base64

from cryptography.hazmat.primitives import serialization
from cryptography import x509

from app.storage.users import create_user, get_user
from app.common.secure_channel import encrypt_envelope, decrypt_envelope
from app.crypto import dh
from app.crypto.pki import (
    load_private_key,
    load_certificate,
    load_ca_certificate,
    verify_peer_certificate,
)


def hash_password(password: str, salt: bytes) -> str:
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def handle_login(payload: dict) -> dict:
    username = payload.get("username", "").strip()
    password = payload.get("password", "")

    if not username or not password:
        return {"status": "error", "message": "missing username or password"}

    user_row = get_user(username)
    if user_row is None:
        return {"status": "error", "message": "no such user"}

    salt_hex, stored_hash = user_row
    salt = bytes.fromhex(salt_hex)
    computed_hash = hash_password(password, salt)

    if computed_hash != stored_hash:
        return {"status": "error", "message": "invalid password"}

    return {"status": "ok", "message": "login successful"}


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


def handle_client(conn, addr, server_cert_pem: str, ca_cert):
    """Handle one client: cert handshake + DH + encrypted REGISTER/LOGIN + chat."""
    print(f"Accepted connection from {addr}")

    try:
        # ---- Certificate handshake ----
        msg = recv_json(conn)
        if not (
            isinstance(msg, dict)
            and msg.get("type") == "client_hello"
            and "cert" in msg
        ):
            raise ValueError("Invalid client_hello message format")

        client_cert_pem = msg["cert"]
        client_cert = load_certificate_bytes(client_cert_pem.encode("utf-8"))

        # Verify client cert using CA and expected CN
        verify_peer_certificate(
            peer_cert=client_cert,
            ca_cert=ca_cert,
            expected_cn="SecureChatClient",
        )

        print("Client certificate validated successfully; sending server_hello.")

        # Send server_hello with server PEM cert
        send_json(
            conn,
            {
                "type": "server_hello",
                "cert": server_cert_pem,
            },
        )

        # ---- Ephemeral Diffie–Hellman key exchange (X25519) ----

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
        srv_priv_ctrl, srv_pub_ctrl = dh.generate_keypair()

        # 3) Compute shared secret
        shared = dh.derive_shared_secret(srv_priv_ctrl, client_pub_bytes)

        # 4) Derive 16-byte AES session key
        session_key = dh.derive_aes_key_from_shared(shared)

        # 5) Send back server's DH public key (base64-encoded)
        srv_pub_b64 = base64.b64encode(srv_pub_ctrl).decode("ascii")
        send_json(
            conn,
            {
                "type": "dh_server_key",
                "pub": srv_pub_b64,
            }
        )

        # 6) Print session key info
        print(f"Server derived session key of length {len(session_key)} bytes")

        # ---- Encrypted REGISTER / LOGIN ----

        # 1) Receive an envelope from the client
        env = recv_json(conn)

        # 2) Decrypt envelope
        payload = decrypt_envelope(session_key, env)

        # 3) Read kind
        kind = payload.get("kind")

        do_chat = False  # track whether we should start chat DH

        if kind == "register":
            if (
                not isinstance(payload, dict)
                or not payload.get("username")
                or not payload.get("password")
            ):
                resp = {"status": "error", "message": "invalid register payload"}
            else:
                username = payload["username"]
                password = payload["password"]

                # generate salt + hash
                salt = os.urandom(16)
                salt_hex = salt.hex()
                hash_hex = hash_password(password, salt)

                # try to insert into DB
                ok = create_user(username, salt_hex, hash_hex)
                if not ok:
                    resp = {"status": "error", "message": "user already exists"}
                else:
                    resp = {"status": "ok", "message": "user registered"}

        elif kind == "login":
            resp = handle_login(payload)
            if resp.get("status") == "ok":
                do_chat = True  # only start chat after successful login

        else:
            resp = {"status": "error", "message": "unknown payload kind"}

        # Encrypt response and send
        resp_env = encrypt_envelope(session_key, resp)
        send_json(conn, resp_env)

        # ---------- Chat session DH + one encrypted message ----------
        if do_chat:
            # 1) Server generates classic DH keypair for CHAT (separate from control DH)
            srv_priv_chat, srv_pub_chat = dh.classic_generate_keypair()

            # 2) Send DH params + server pub to client, encrypted with control session_key
            chat_dh_msg = {
                "kind": "chat_dh_params",
                "p": str(dh.CLASSIC_P),
                "g": str(dh.CLASSIC_G),
                "A": str(srv_pub_chat),
            }
            env_dh = encrypt_envelope(session_key, chat_dh_msg)
            send_json(conn, env_dh)

            # 3) Receive client's DH response (B)
            env2 = recv_json(conn)
            chat_resp = decrypt_envelope(session_key, env2)
            if chat_resp.get("kind") != "chat_dh_response" or "B" not in chat_resp:
                raise ValueError("Invalid chat_dh_response")

            B = int(chat_resp["B"])

            # 4) Derive chat shared secret and AES key
            shared_int = dh.classic_derive_shared(srv_priv_chat, B)
            chat_key = dh.classic_derive_aes_key_from_shared(shared_int)
            print(f"Server chat key length: {len(chat_key)} bytes")

            # 5) Receive one encrypted chat message under chat_key
            env3 = recv_json(conn)
            chat_payload = decrypt_envelope(chat_key, env3)
            if chat_payload.get("type") == "chat_msg":
                print("Client says:", chat_payload.get("text"))

                # 6) Send encrypted ACK under chat_key
                ack = {"type": "chat_ack", "message": "message received"}
                ack_env = encrypt_envelope(chat_key, ack)
                send_json(conn, ack_env)
            else:
                print("Unexpected chat payload:", chat_payload)

    except Exception as e:
        print(f"Fatal server error for {addr}: {e}")
        try:
            # Best-effort error message (not encrypted)
            send_json(conn, {"type": "error", "message": str(e)})
        except Exception:
            pass  # ignore send error


def main():
    # Load keys/certs
    server_key = load_private_key("certs/server.key")  # reserved for signatures later
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
        srv.listen(5)
        print(f"Server listening on {HOST}:{PORT}")

        while True:
            try:
                conn, addr = srv.accept()
                with conn:
                    handle_client(conn, addr, server_cert_pem, ca_cert)
            except KeyboardInterrupt:
                print("Server shutting down on Ctrl+C")
                break
            except Exception as e:
                print(f"Top-level server error: {e}")


if __name__ == "__main__":
    main()
