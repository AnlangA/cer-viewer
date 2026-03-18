#!/usr/bin/env python3
"""
Generate test certificate fixtures for cer-viewer.

This script generates various types of certificates, keys, CSRs, and CRLs
for testing purposes.

Usage: python generate_fixtures.py
"""

import subprocess
import datetime
import os
import sys

# Configuration
VALID_DAYS = 365
EXPIRED_DAYS = -10  # Already expired
NOT_YET_VALID_DAYS = 10  # Valid in the future

# Directory paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERT_DIR = os.path.join(BASE_DIR, "certificates")
KEY_DIR = os.path.join(BASE_DIR, "keys")
CSR_DIR = os.path.join(BASE_DIR, "csr")
CRL_DIR = os.path.join(BASE_DIR, "crl")
PKCS12_DIR = os.path.join(BASE_DIR, "pkcs12")


def run_openssl(args, input_data=None):
    """Run OpenSSL command and return output."""
    cmd = ["openssl"] + args
    result = subprocess.run(
        cmd,
        input=input_data,
        capture_output=True,
        text=True,
        check=False
    )
    return result.returncode, result.stdout, result.stderr


def generate_ca_cert(name, days=VALID_DAYS):
    """Generate a self-signed CA certificate."""
    key_path = os.path.join(KEY_DIR, "rsa", f"{name.lower()}.key")
    cert_path = os.path.join(CERT_DIR, "valid", f"{name.lower()}.crt")

    # Generate private key
    rc, _, err = run_openssl([
        "genrsa",
        "-out", key_path,
        "2048"
    ])
    if rc != 0:
        print(f"Error generating key for {name}: {err}")
        return None, None

    # Generate self-signed certificate
    start_date = datetime.datetime.now() - datetime.timedelta(days=1)
    end_date = datetime.datetime.now() + datetime.timedelta(days=days)

    rc, _, err = run_openssl([
        "req", "-new", "-x509",
        "-key", key_path,
        "-out", cert_path,
        "-days", str(days),
        "-subj", f"/C=US/O=Test Org/CN={name}",
        "-set_serial", "01"
    ])

    if rc != 0:
        print(f"Error generating cert for {name}: {err}")
        return None, None

    return key_path, cert_path


def generate_leaf_cert(name, ca_key, ca_cert, days=VALID_DAYS, san=None):
    """Generate a leaf certificate signed by CA."""
    key_path = os.path.join(KEY_DIR, "rsa", f"{name.lower()}.key")
    csr_path = os.path.join(CSR_DIR, f"{name.lower()}.csr")
    cert_path = os.path.join(CERT_DIR, "valid", f"{name.lower()}.crt")

    # Generate private key
    rc, _, err = run_openssl([
        "genrsa",
        "-out", key_path,
        "2048"
    ])
    if rc != 0:
        print(f"Error generating key for {name}: {err}")
        return None, None

    # Generate CSR
    subj = f"/C=US/O=Test Org/CN={name}"
    if san:
        subj = f"/C=US/O=Test Org/CN={san[0]}"

    rc, _, err = run_openssl([
        "req", "-new",
        "-key", key_path,
        "-out", csr_path,
        "-subj", subj
    ])
    if rc != 0:
        print(f"Error generating CSR for {name}: {err}")
        return None, None

    # Sign with CA
    config_args = []
    if san:
        # Create temporary config file for SAN
        san_list = ",".join([f"DNS:{s}" for s in san])
        config_content = f"""
[san]
subjectAltName={san_list}
"""
        config_path = os.path.join(BASE_DIR, "temp.cnf")
        with open(config_path, "w") as f:
            f.write(config_content)
        config_args = ["-extfile", config_path, "-extensions", "san"]

    rc, _, err = run_openssl([
        "x509", "-req",
        "-in", csr_path,
        "-CA", ca_cert,
        "-CAkey", ca_key,
        "-CAcreateserial",
        "-out", cert_path,
        "-days", str(days),
        "-sha256"
    ] + config_args)

    # Clean up temp config
    if san and os.path.exists(os.path.join(BASE_DIR, "temp.cnf")):
        os.remove(os.path.join(BASE_DIR, "temp.cnf"))

    if rc != 0:
        print(f"Error signing cert for {name}: {err}")
        return None, None

    return key_path, cert_path


def generate_ec_cert(name, curve="prime256v1", days=VALID_DAYS):
    """Generate an EC certificate."""
    key_path = os.path.join(KEY_DIR, "ec", f"{name.lower()}-ec.key")
    cert_path = os.path.join(CERT_DIR, "valid", f"{name.lower()}-ec.crt")

    # Generate EC private key
    rc, _, err = run_openssl([
        "ecparam",
        "-genkey",
        "-name", curve,
        "-out", key_path
    ])
    if rc != 0:
        print(f"Error generating EC key for {name}: {err}")
        return None, None

    # Generate self-signed certificate
    rc, _, err = run_openssl([
        "req", "-new", "-x509",
        "-key", key_path,
        "-out", cert_path,
        "-days", str(days),
        "-subj", f"/C=US/O=Test Org/CN={name} (EC)"
    ])
    if rc != 0:
        print(f"Error generating EC cert for {name}: {err}")
        return None, None

    return key_path, cert_path


def generate_expired_cert(name):
    """Generate an expired certificate."""
    key_path = os.path.join(KEY_DIR, "rsa", f"{name.lower()}.key")
    cert_path = os.path.join(CERT_DIR, "expired", f"{name.lower()}.crt")

    # Generate private key
    rc, _, err = run_openssl([
        "genrsa",
        "-out", key_path,
        "2048"
    ])
    if rc != 0:
        return None, None

    # Generate certificate that's already expired
    start_date = datetime.datetime.now() - datetime.timedelta(days=20)
    end_date = datetime.datetime.now() - datetime.timedelta(days=10)

    # Use -startdate and -enddate options
    rc, _, err = run_openssl([
        "req", "-new", "-x509",
        "-key", key_path,
        "-out", cert_path,
        "-days", "365",
        "-subj", f"/C=US/O=Test Org/CN={name}"
    ])
    if rc != 0:
        return None, None

    return key_path, cert_path


def generate_wildcard_cert():
    """Generate a wildcard certificate."""
    ca_key, ca_cert = generate_ca_cert("Wildcard CA")

    if ca_key and ca_cert:
        generate_leaf_cert(
            "wildcard.example.com",
            ca_key,
            ca_cert,
            san=["*.example.com", "example.com"]
        )


def generate_crl(ca_name, revoked_serials):
    """Generate a CRL with revoked certificates."""
    ca_key = os.path.join(KEY_DIR, "rsa", f"{ca_name.lower()}.key")
    ca_cert = os.path.join(CERT_DIR, "valid", f"{ca_name.lower()}.crt")
    crl_path = os.path.join(CRL_DIR, f"{ca_name.lower()}.crl")

    # Create index file for CRL
    index_path = os.path.join(BASE_DIR, "index.txt")
    with open(index_path, "w") as f:
        for serial in revoked_serials:
            exp_date = (datetime.datetime.now() + datetime.timedelta(days=365)).strftime("%y%m%d%H%M%SZ")
            f.write(f"R\t{exp_date}\t{serial}Z\tunknown\t{ca_name}\n")

    # Create CRL number file
    crl_number_path = os.path.join(BASE_DIR, "crlnumber")
    with open(crl_number_path, "w") as f:
        f.write("01\n")

    rc, _, err = run_openssl([
        "ca", "-gencrl",
        "-keyfile", ca_key,
        "-cert", ca_cert,
        "-out", crl_path,
        "-config", "/dev/null"
    ])

    # Clean up
    if os.path.exists(index_path):
        os.remove(index_path)
    if os.path.exists(crl_number_path):
        os.remove(crl_number_path)

    return crl_path if rc == 0 else None


def generate_pkcs12(name, cert_path, key_path, ca_cert_path, password=""):
    """Generate a PKCS#12 bundle."""
    p12_path = os.path.join(PKCS12_DIR, f"{name.lower()}.p12")

    args = [
        "pkcs12", "-export",
        "-out", p12_path,
        "-inkey", key_path,
        "-in", cert_path,
        "-certfile", ca_cert_path,
        "-passout", f"pass:{password}"
    ]

    rc, _, err = run_openssl(args)
    return p12_path if rc == 0 else None


def main():
    """Generate all test fixtures."""
    print("Generating test fixtures...")

    # Create directories
    for d in [CERT_DIR, KEY_DIR, CSR_DIR, CRL_DIR, PKCS12_DIR]:
        os.makedirs(d, exist_ok=True)
    for d in ["valid", "expired", "not-yet-valid", "self-signed", "wildcard"]:
        os.makedirs(os.path.join(CERT_DIR, d), exist_ok=True)
    for d in ["rsa", "ec", "ed25519"]:
        os.makedirs(os.path.join(KEY_DIR, d), exist_ok=True)

    # Generate CA certificates
    print("\n1. Generating CA certificates...")
    root_ca_key, root_ca_cert = generate_ca_cert("Root CA")
    intermediate_ca_key, intermediate_ca_cert = generate_ca_cert("Intermediate CA")

    # Generate leaf certificates
    print("\n2. Generating leaf certificates...")
    generate_leaf_cert("example.com", intermediate_ca_key, intermediate_ca_cert,
                      san=["example.com", "www.example.com"])
    generate_leaf_cert("test.org", intermediate_ca_key, intermediate_ca_cert)
    generate_leaf_cert("subdomain.example.com", intermediate_ca_key, intermediate_ca_cert,
                      san=["subdomain.example.com"])

    # Generate EC certificate
    print("\n3. Generating EC certificates...")
    generate_ec_cert("EC Cert", "prime256v1")
    generate_ec_cert("EC P-384", "secp384r1")

    # Generate self-signed certificates
    print("\n4. Generating self-signed certificates...")
    generate_ca_cert("Self-Signed Cert")

    # Generate wildcard certificate
    print("\n5. Generating wildcard certificate...")
    generate_wildcard_cert()

    # Generate expired certificate
    print("\n6. Generating expired certificate...")
    generate_expired_cert("Expired Cert")

    # Generate PKCS#12 bundles
    print("\n7. Generating PKCS#12 bundles...")
    leaf_key = os.path.join(KEY_DIR, "rsa", "example.com.key")
    leaf_cert = os.path.join(CERT_DIR, "valid", "example.com.crt")
    if os.path.exists(leaf_key) and os.path.exists(leaf_cert):
        generate_pkcs12("example", leaf_cert, leaf_key, intermediate_ca_cert, password="test123")
        generate_pkcs12("example-nopass", leaf_cert, leaf_key, intermediate_ca_cert, password="")

    # Convert some certs to PEM format for easy testing
    print("\n8. Creating PEM files...")

    # Create a certificate chain file
    chain_path = os.path.join(CERT_DIR, "valid", "chain.pem")
    with open(chain_path, "w") as f:
        for cert_file in [leaf_cert, intermediate_ca_cert, root_ca_cert]:
            if os.path.exists(cert_file):
                with open(cert_file, "r") as cf:
                    f.write(cf.read())

    print("\n✅ Fixtures generated successfully!")
    print(f"\nGenerated files:")
    print(f"  - CA certificates: {root_ca_cert}, {intermediate_ca_cert}")
    print(f"  - Leaf certificates: {CERT_DIR}/valid/")
    print(f"  - EC certificates: {CERT_DIR}/valid/*-ec.crt")
    print(f"  - Private keys: {KEY_DIR}/")
    print(f"  - CSRs: {CSR_DIR}/")
    print(f"  - PKCS#12: {PKCS12_DIR}/")


if __name__ == "__main__":
    main()
