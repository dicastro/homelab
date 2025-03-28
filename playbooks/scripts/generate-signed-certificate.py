import os
import sys
import importlib.metadata
import subprocess
import argparse
import json


# Default expiration time (100 years)
DEFAULT_EXPIRATION_DAYS = 365 * 100

REQUIRED_PACKAGES = ["cryptography"]


def parse_args():
    parser = argparse.ArgumentParser(description="Generate and manage signed certificates.")
    parser.add_argument("--base-path", help="Base path to store the certificates", default="ca")
    parser.add_argument("--ca-alias", required=True, help="CA alias to sign the certificate with")
    parser.add_argument("--ca-cn", help="Common Name (CN) for the CA certificate (in case a new CA is generated)")
    parser.add_argument("--ca-expiration-days", type=int, default=DEFAULT_EXPIRATION_DAYS, help=f"CA expiration (default {DEFAULT_EXPIRATION_DAYS} days)")
    parser.add_argument("--signed-alias", required=True, help="Signed certificate alias")
    parser.add_argument("--signed-cn", required=True, help="Common Name (CN) for the signed certificate")
    parser.add_argument("--signed-san-ip", action="append", default=[], help="Signed certificate IP address for SAN (can be used multiple times)")
    parser.add_argument("--signed-san-dns", action="append", default=[], help="Signed certificate DNS name for SAN (can be used multiple times)")
    parser.add_argument("--signed-expiration-days", type=int, default=DEFAULT_EXPIRATION_DAYS, help=f"Signed certificate expiration (default {DEFAULT_EXPIRATION_DAYS} days)")
    parser.add_argument("--force", action="store_true", help="Force certificate regeneration")
    parser.add_argument("--renew", action="store_true", help="Renew certificate if expired")
    parser.add_argument("--output-format", choices=["console", "ansible"], default="console", help="Output format (default: console)")
    
    return parser.parse_args()


def is_running_in_venv():
    return (
        hasattr(sys, 'real_prefix')
        or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
        or 'VIRTUAL_ENV' in os.environ
    )


def log_message(message, output_format="console"):
    if output_format == "ansible":
        print(f"[INFO] {message}", file=sys.stderr)
    else:
        print(f"[INFO] {message}")


def end_script(status, message, changed=False, details=None, output_format="console"):
    response = {
        "status": status,
        "message": message,
        "changed": changed,
        "details": details or {},
    }

    if output_format == "ansible":
        print(json.dumps(response))
    else:
        print(f"[{status.upper()}] {message}")
        if details:
            for key, value in details.items():
                print(f"  - {key}: {value}")

    sys.exit(0 if status == "success" else 1)


def install_required_packages_silently(package):
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "--quiet", "--no-input", "--disable-pip-version-check", package],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )


def check_and_install_packages():
    for package in REQUIRED_PACKAGES:
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            log_message(f"Missing package: {package}", output_format=args.output_format)
            log_message(f"Installing missing package '{package}'...", output_format=args.output_format)
            install_required_packages_silently(package)
        except Exception as e:
            end_script("failure", f"Error checking if package '{package}' is already installed", output_format=args.output_format)


args = parse_args()

if not is_running_in_venv():
    end_script("failure", "This script must be run inside a virtual environment", output_format=args.output_format)

# Ensure required packages are installed before continuing
check_and_install_packages()


import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from ipaddress import ip_address


BASE_CA_PATH = f"{args.base_path}/certificates"
os.makedirs(BASE_CA_PATH, exist_ok=True)

KEY_SIZE = 4096

def get_now():
    return datetime.datetime.now(datetime.timezone.utc)


def get_signed_cert_paths(signed_alias):
    return (
        get_signed_cert_crt_path(signed_alias),
        get_signed_cert_key_path(signed_alias),
    )


def get_signed_cert_crt_path(signed_alias):
    return os.path.join(BASE_CA_PATH, "signed", signed_alias, f"{signed_alias}_crt.pem")


def get_signed_cert_key_path(signed_alias):
    return os.path.join(BASE_CA_PATH, "signed", signed_alias, f"{signed_alias}_key.pem")


def get_ca_paths(ca_alias):
    return (
        get_ca_crt_path(ca_alias),
        get_ca_key_path(ca_alias),
        get_ca_serial_path(ca_alias),
    )


def get_ca_crt_path(ca_alias):
    return os.path.join(BASE_CA_PATH, f"{ca_alias}_root_ca_crt.pem")


def get_ca_key_path(ca_alias):
    return os.path.join(BASE_CA_PATH, f"{ca_alias}_root_ca_key.pem")


def get_ca_serial_path(ca_alias):
    return os.path.join(BASE_CA_PATH, f"{ca_alias}_root_ca.srl")


def _path_not_exists(path):
    return not os.path.exists(path)


def load_crt(crt_path):
    if _path_not_exists(crt_path):
        return None

    with open(crt_path, "rb") as crt_file:
        return x509.load_pem_x509_certificate(crt_file.read(), default_backend())


def load_key(key_path):
    if _path_not_exists(key_path):
        return None

    with open(key_path, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())


def is_certificate_expired(cert):
    return cert.not_valid_after_utc < get_now()


def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
        backend=default_backend(),
    )


def generate_ca(ca_alias, ca_cn, ca_expiration_days, ca_crt_path, ca_key_path, ca_serial_path):
    key = generate_key()
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_cn)])
    
    now = get_now()

    ca_basic_constraints = x509.BasicConstraints(ca=True, path_length=None)

    # Generate SKI from CA public key
    ca_subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(key.public_key())

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=ca_expiration_days))
        .add_extension(ca_basic_constraints, critical=True)
        .add_extension(ca_subject_key_identifier, critical=False)
        .sign(key, hashes.SHA256(), default_backend())
    )

    save_certificate(cert, ca_crt_path)
    save_key(key, ca_key_path)

    with open(ca_serial_path, "w") as serial_file:
        serial_file.write("1")

    return cert, key


def generate_csr(signed_key, signed_cn, signed_san_ips, signed_san_dns):
    signed_san_list = []
    for signed_san_ip in signed_san_ips:
        signed_san_list.append(x509.IPAddress(ip_address(signed_san_ip)))
    for signed_san_dns in signed_san_dns:
        signed_san_list.append(x509.DNSName(signed_san_dns))

    signed_csr_builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, signed_cn)])
    )

    if signed_san_list:
        signed_csr_builder = signed_csr_builder.add_extension(x509.SubjectAlternativeName(signed_san_list), critical=False)

    return signed_csr_builder.sign(signed_key, hashes.SHA256(), default_backend())


def get_subject_key_identifier(cert):
    public_key = cert.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    else:
        raise ValueError("Unsupported public key type")

    hash_obj = hashes.Hash(hashes.SHA1(), backend=default_backend())
    hash_obj.update(public_key_bytes)

    # Use SHA-1 hash to generate the SKI (this is the standard)
    return hash_obj.finalize()


def sign_certificate(signed_csr, signed_expiration_days, ca_cert, ca_key, ca_serial_path):    
    with open(ca_serial_path, "r+") as serial_file:
        serial_number = int(serial_file.read().strip())
        serial_file.seek(0)
        serial_file.write(str(serial_number + 1))
        serial_file.truncate()

    now = get_now()

    signed_basic_constraints = x509.BasicConstraints(ca=False, path_length=None)

    # Generate Subject Key Identifier
    signed_subject_key_identifier = x509.SubjectKeyIdentifier.from_public_key(signed_csr.public_key())

    # Get the SKI from the CA certificate
    try:
        ca_subject_key_identifier = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    except x509.ExtensionNotFound:
        ca_subject_key_identifier = get_subject_key_identifier(ca_cert)

    # Generate Authority Key Identifier
    signed_authority_key_identifier = x509.AuthorityKeyIdentifier(
        key_identifier=ca_subject_key_identifier,
        authority_cert_issuer=[x509.DirectoryName(ca_cert.subject)],
        authority_cert_serial_number=ca_cert.serial_number,
    )

    signed_builder = (
        x509.CertificateBuilder()
        .subject_name(signed_csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(signed_csr.public_key())
        .serial_number(serial_number)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=signed_expiration_days))
        .add_extension(signed_basic_constraints, critical=True)
        .add_extension(signed_subject_key_identifier, critical=False)
        .add_extension(signed_authority_key_identifier, critical=False)
    )

    try:
        signed_san_extension = signed_csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        signed_builder = signed_builder.add_extension(x509.SubjectAlternativeName(signed_san_extension.value), critical=False)
    except x509.ExtensionNotFound:
        pass
    
    return signed_builder.sign(ca_key, hashes.SHA256(), default_backend())


def save_certificate(cert, cert_path):
    pem_data = cert.public_bytes(serialization.Encoding.PEM).rstrip(b"\n")

    with open(cert_path, "wb") as f:
        f.write(pem_data)


def save_key(key, key_path):
    pem_data = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).rstrip(b"\n")

    with open(key_path, "wb") as f:
        f.write(pem_data)


def get_log_details(ca_crt_path, signed_crt_path, signed_key_path):
    return {"ca-crt-path": ca_crt_path, "signed-crt-path": signed_crt_path, "signed-key-path": signed_key_path}


def generate_signed_certificate():
    signed_crt_path, signed_key_path = get_signed_cert_paths(args.signed_alias)
    ca_crt_path, ca_key_path, ca_serial_path = get_ca_paths(args.ca_alias)

    if _path_not_exists(ca_crt_path) or _path_not_exists(ca_key_path) or _path_not_exists(ca_serial_path):
        log_message("CA not found, generating new CA...", output_format=args.output_format)

        if not args.ca_cn:
            end_script("failure", "--ca-cn is required when generating a new CA", output_format=args.output_format)

        ca_crt, ca_key = generate_ca(args.ca_alias, args.ca_cn, args.ca_expiration_days, ca_crt_path, ca_key_path, ca_serial_path)

        log_message("New CA generated!", output_format=args.output_format)
    else:
        ca_crt = load_crt(ca_crt_path)
        ca_key = load_key(ca_key_path)

    signed_crt = load_crt(signed_crt_path)

    if signed_crt:
        if not is_certificate_expired(signed_crt) and not args.force:
            end_script("success", "Signed certificate already present and valid, no renewal needed", changed=False, details=get_log_details(ca_crt_path, signed_crt_path, signed_key_path), output_format=args.output_format)
        elif is_certificate_expired(signed_crt) and not args.renew:
            end_script("failure", "Signed certificate expired, use --renew to regenerate", output_format=args.output_format)

    signed_key = generate_key()
    signed_csr = generate_csr(signed_key, args.signed_cn, args.signed_san_ip, args.signed_san_dns)
    signed_crt_new = sign_certificate(signed_csr, args.signed_expiration_days, ca_crt, ca_key, ca_serial_path)

    os.makedirs(os.path.dirname(signed_crt_path), exist_ok=True)
    save_certificate(signed_crt_new, signed_crt_path)
    save_key(signed_key, signed_key_path)

    end_script("success", "Signed certificate generated successfully", changed=True, details=get_log_details(ca_crt_path, signed_crt_path, signed_key_path), output_format=args.output_format)



if __name__ == "__main__":
    generate_signed_certificate()
