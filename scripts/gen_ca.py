"""Create Root CA (RSA + self-signed X.509) using cryptography."""

import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

def main():
    # Ensure certs directory exists
    certs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "certs")
    os.makedirs(certs_dir, exist_ok=True)
    key_path = os.path.join(certs_dir, "ca.key")
    crt_path = os.path.join(certs_dir, "ca.crt")

    # Generate 4096-bit RSA private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Write the private key to file, PEM encoded
    with open(key_path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # Subject and issuer are the same (self-signed)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChatRootCA"),
    ])

    now = datetime.utcnow()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )

    # Write certificate to file, PEM encoded
    with open(crt_path, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"CA private key saved to {key_path}")
    print(f"CA certificate saved to {crt_path}")

if __name__ == "__main__":
    main()
