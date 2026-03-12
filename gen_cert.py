import subprocess
import sys
import os

os.makedirs("certs", exist_ok=True)

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509 import SubjectAlternativeName, DNSName, IPAddress
    import ipaddress
    import datetime

    print("Generating certificate using cryptography library...")

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                DNSName("localhost"),
                IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open("certs/server.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open("certs/server.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("Done!")
    print("  certs/server.key  created")
    print("  certs/server.crt  created")

except ImportError:
    print("cryptography library not found. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography"])
    print("Installed! Now run this script again:")
    print("  python gen_cert.py")