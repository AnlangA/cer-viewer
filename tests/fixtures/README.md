# Test Fixtures

This directory contains test certificates and cryptographic data for testing cer-viewer.

## Structure

```
fixtures/
├── certificates/         # X.509 certificates
│   ├── valid/           # Currently valid certificates
│   ├── expired/         # Expired certificates
│   ├── not-yet-valid/   # Certificates with future validity dates
│   ├── self-signed/     # Self-signed certificates
│   └── wildcard/        # Wildcard certificates
├── keys/                # Private keys (test only, never production)
│   ├── rsa/            # RSA private keys (2048-bit)
│   ├── ec/             # Elliptic Curve keys (P-256, P-384)
│   └── ed25519/        # Ed25519 keys (not yet generated)
├── csr/                 # Certificate Signing Requests
├── crl/                 # Certificate Revocation Lists
├── pkcs12/              # PKCS#12 archives
├── generate_fixtures.py # Fixture generation script
└── README.md            # This file
```

## Available Fixtures

### Certificates

#### Valid Certificates (`certificates/valid/`)
- `root ca.crt` - Self-signed Root CA certificate
- `intermediate ca.crt` - Self-signed Intermediate CA certificate
- `example.com.crt` - Leaf certificate for example.com
- `subdomain.example.com.crt` - Leaf certificate for subdomain
- `test.org.crt` - Leaf certificate for test.org
- `wildcard.example.com.crt` - Wildcard certificate for *.example.com
- `ec cert-ec.crt` - EC certificate (P-256 curve)
- `ec p-384-ec.crt` - EC certificate (P-384 curve)
- `self-signed cert.crt` - Generic self-signed certificate
- `chain.pem` - Combined certificate chain (leaf + intermediate + root)

#### Expired Certificates (`certificates/expired/`)
- `expired cert.crt` - Certificate that has expired

### Private Keys (`keys/`)

#### RSA Keys (`keys/rsa/`)
- `root ca.key` - Root CA private key
- `intermediate ca.key` - Intermediate CA private key
- `example.com.key` - Leaf certificate private key
- `subdomain.example.com.key` - Subdomain private key
- `test.org.key` - Test.org private key
- `*.example.com.key` - Wildcard certificate private key
- `self-signed cert.key` - Self-signed certificate private key
- `expired cert.key` - Expired certificate private key
- `wildcard ca.key` - Wildcard CA private key

#### EC Keys (`keys/ec/`)
- `ec cert-ec.key` - EC private key (P-256)
- `ec p-384-ec.key` - EC private key (P-384)

### Certificate Signing Requests (`csr/`)
- `example.com.csr` - CSR for example.com
- `subdomain.example.com.csr` - CSR for subdomain
- `test.org.csr` - CSR for test.org
- `wildcard.example.com.csr` - CSR for wildcard certificate

### PKCS#12 Archives (`pkcs12/`)
- `example.p12` - PKCS#12 bundle with password "test123"
- `example-nopass.p12` - PKCS#12 bundle without password

## Generating New Fixtures

Run the generation script:

```bash
cd tests/fixtures
python3 generate_fixtures.py
```

This requires:
- Python 3.6+
- OpenSSL command-line tool

## Manual Certificate Generation

### Generate a self-signed CA

```bash
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt -days 3650 -nodes \
  -subj "/C=US/O=Test Org/CN=Test CA"
```

### Generate a leaf certificate

```bash
# Generate private key
openssl genrsa -out leaf.key 2048

# Generate CSR
openssl req -new -key leaf.key -out leaf.csr \
  -subj "/C=US/O=Test Org/CN=example.com"

# Sign with CA
openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out leaf.crt -days 365 -sha256
```

### Generate a PKCS#12 bundle

```bash
openssl pkcs12 -export -out bundle.p12 -inkey leaf.key -in leaf.crt \
  -certfile ca.crt -passout pass:test123
```

### Generate an EC certificate

```bash
# Generate EC private key
openssl ecparam -genkey -name prime256v1 -out ec.key

# Generate self-signed certificate
openssl req -new -x509 -key ec.key -out ec.crt -days 365 \
  -subj "/C=US/O=Test Org/CN=EC Cert"
```

### Generate a wildcard certificate

```bash
# Generate private key
openssl genrsa -out wildcard.key 2048

# Generate CSR
openssl req -new -key wildcard.key -out wildcard.csr \
  -subj "/C=US/O=Test Org/CN=*.example.com"

# Create config with SAN
cat > san.cnf << EOF
[san]
subjectAltName=DNS:*.example.com,DNS:example.com
EOF

# Sign with CA
openssl x509 -req -in wildcard.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out wildcard.crt -days 365 -sha256 \
  -extfile san.cnf -extensions san
```

## Security Notes

**IMPORTANT**: All private keys in this directory are for testing purposes only.

### Key Security
- All keys are 2048-bit RSA or standard EC curves
- All keys use simple or no passwords
- **Never use these keys in production**
- **Never commit real private keys to the repository**

### Passwords Used
- `example.p12`: password is `test123`
- `example-nopass.p12`: no password
- All other keys: no password

## Test Coverage

The fixtures cover:
- ✅ Valid certificates (leaf, intermediate, root)
- ✅ Self-signed certificates
- ✅ Wildcard certificates
- ✅ Expired certificates
- ✅ EC certificates (P-256, P-384)
- ✅ Certificate chains
- ✅ RSA private keys
- ✅ EC private keys
- ✅ Certificate Signing Requests
- ✅ PKCS#12 bundles (with and without password)
- ⏳ Ed25519 keys (not yet generated)
- ⏳ CRLs (not yet generated)
- ⏳ OCSP responses (not yet generated)
