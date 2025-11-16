"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import argparse
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.x509 import DNSName, SubjectAlternativeName
from datetime import datetime, timedelta

def main():
    parser = argparse.ArgumentParser(
        description="Issue server/client cert signed by Root CA"
    )
    parser.add_argument(
        "role",
        choices=["server", "client"],
        help="Which certificate to issue: 'server' or 'client'"
    )
    args = parser.parse_args()
    role = args.role

    # Set CN, output paths, etc.
    cn_name = "SecureChatServer" if role == "server" else "SecureChatClient"
    out_key = f"{role}.key"
    out_crt = f"{role}.crt"
    certs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "certs")
    os.makedirs(certs_dir, exist_ok=True)
    key_path = os.path.join(certs_dir, out_key)
    crt_path = os.path.join(certs_dir, out_crt)
    ca_key_path = os.path.join(certs_dir, "ca.key")
    ca_crt_path = os.path.join(certs_dir, "ca.crt")

    # Generate RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Load CA key and cert
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_crt_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Build subject/CSR/cert
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn_name),
    ])

    now = datetime.utcnow()
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            SubjectAlternativeName([DNSName(cn_name)]),
            critical=False
        )
    )

    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"{role.capitalize()} private key saved to {key_path}")
    print(f"{role.capitalize()} certificate saved to {crt_path}")

if __name__ == "__main__":
    main()
