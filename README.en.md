# cer-viewer

A modern X.509 certificate and CSR viewer built with Rust. GUI powered by [egui](https://github.com/emilk/egui)/[eframe](https://github.com/emilk/egui/tree/master/crates/eframe), with a full-featured CLI mode.

[中文](README.md) | English

[![CI](https://github.com/AnlangA/cer-viewer/actions/workflows/ci.yml/badge.svg)](https://github.com/AnlangA/cer-viewer/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

## Features

### Certificate & CSR Viewing

- PEM (`.pem`, `.crt`) and DER (`.cer`, `.der`) X.509 certificate parsing
- CSR (PKCS#10) file support (`.csr`, `.p10`) with extension attribute parsing
- Collapsible field tree: version, serial number, signature algorithm, issuer, subject, validity, public key info, extensions, signature value, fingerprints
- 18 X.509 v3 extensions: SAN, Key Usage, Basic Constraints, EKU, AIA, CRL Distribution Points, Certificate Policies, SCT/CT, Name Constraints, Policy Mappings, Policy Constraints, Inhibit Any Policy, Subject Info Access, Issuer Alternative Name, NS Cert Type, etc.
- SHA-256 and SHA-1 fingerprint calculation

### Certificate Chain

- Automatic chain building from leaf to root CA
- Automatic intermediate certificate download via AIA CA Issuers (`network` feature)
- Cryptographic signature verification
- Issuer-Subject chain validation
- System trust store integration

### CLI Tools

- Subcommands: `chain`, `extract`, `verify`, `convert`, `fingerprint`, `cache`
- Output formats: `text`, `json`, `table`
- Pipe/stdin input support
- Colored output (can be disabled)

### GUI

- Dark/light theme switching
- Multi-tab document support
- Collapsible field tree with one-click copy
- Certificate comparison and chain visualization
- Certificate generation dialog (self-signed certs & CSRs)
- PKCS#12 password dialog
- Sensitive data detection with security warnings

### Security

- Automatic sensitive data detection (private keys, passwords, key material)
- Copy warnings for sensitive data
- `ProtectedString` with `zeroize` for automatic memory erasure
- Password-protected PKCS#12 file detection

### Certificate Generation

- Self-signed certificates (RSA 2048/3072/4096, EC P-256/P-384/P-521)
- CSR generation
- Subject Alternative Names (DNS names & IP addresses)
- CA certificate generation
- PEM and DER output formats

## Supported Formats

| Format | Extension | Description | Feature |
|--------|-----------|-------------|---------|
| X.509 Certificate (PEM) | `.pem`, `.crt` | Base64 encoded | Default |
| X.509 Certificate (DER) | `.cer`, `.der` | Binary ASN.1 encoding | Default |
| CSR / PKCS#10 | `.csr`, `.p10` | Certificate Signing Request | Default |
| PKCS#12 / PFX | `.p12`, `.pfx` | Certificate and private key bundle | `pkcs12` |
| CMS / PKCS#7 | `.p7b`, `.p7c` | Signed data (certificate chain) | `pkcs12` |
| Private Key (PKCS#8) | `.key`, `.pem` | General private key format | `private-keys` |
| Private Key (EC/SEC1) | `.key`, `.pem` | EC private key | `private-keys` |
| Private Key (RSA/PKCS#1) | `.key`, `.pem` | RSA private key | `private-keys` |

## Installation

### Pre-built Binaries

Download from [Releases](https://github.com/AnlangA/cer-viewer/releases):

- Windows (x86_64)
- macOS (Apple Silicon / Intel)
- Linux (x86_64)

### Build from Source

**Prerequisites:** [Rust toolchain](https://rustup.rs/) (stable, minimum 1.80)

```bash
git clone https://github.com/AnlangA/cer-viewer.git
cd cer-viewer
cargo build --release
```

Binary at `target/release/cer-viewer`.

#### Feature Flags

```bash
cargo build --release                              # Default (all features)
cargo build --release --no-default-features        # Minimal
cargo build --release --features full-formats      # All format support
cargo build --release --features network           # Network only
```

| Feature | Description | Default |
|---------|-------------|---------|
| `pkcs12` | PKCS#12 and CMS/PKCS#7 parsing | Enabled |
| `private-keys` | Private key parsing (PKCS#8, EC, RSA) | Enabled |
| `network` | Network operations (OCSP/CRL, chain completion) | Enabled |
| `full-formats` | All format support (`pkcs12` + `private-keys`) | -- |

#### Linux Dependencies

```bash
sudo apt-get install -y libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libx11-dev libxi-dev libgl1-mesa-dev
```

## Usage

### GUI Mode

```bash
cer-viewer
```

- Drag and drop files to open
- Click fields to copy values to clipboard
- Right-click tabs to close others
- Toggle dark/light theme from toolbar

### CLI Mode

```bash
cer-viewer certificate.pem                         # View certificate
cer-viewer --format json certificate.pem           # JSON output
cer-viewer --format table certificate.pem          # Table output
cer-viewer --fields subject,issuer certificate.pem  # Specific fields
cer-viewer --chain leaf.crt intermediate.crt root.crt
cat certificate.pem | cer-viewer -                 # From stdin
```

#### Subcommands

**chain** -- Certificate chain analysis

```bash
cer-viewer chain leaf.crt intermediate.crt root.crt
cer-viewer chain --format json leaf.crt intermediate.crt root.crt
```

**extract** -- Extract specific fields

```bash
cer-viewer extract certificate.pem subject         # Certificate fields
cer-viewer extract certificate.pem serial
cer-viewer extract certificate.pem sha256
cer-viewer extract certificate.pem pem
cer-viewer extract request.csr subject             # CSR fields
cer-viewer extract request.csr signature
```

**verify** -- Verify certificate

```bash
cer-viewer verify certificate.pem
cer-viewer verify --trust-store ca-bundle.crt certificate.pem
cer-viewer verify --hostname example.com certificate.pem
```

**convert** -- Format conversion

```bash
cer-viewer convert input.pem output.der --to der
cer-viewer convert input.der output.pem --to pem
```

**fingerprint** -- Show fingerprints

```bash
cer-viewer fingerprint certificate.pem
cer-viewer fingerprint cert1.pem cert2.pem
```

**cache** -- Cache management

```bash
cer-viewer cache info                              # Cache info
cer-viewer cache list                              # List entries
cer-viewer cache cleanup --days 30                 # Clean expired
cer-viewer cache clear                             # Clear all
```

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd/Ctrl + O` | Open file dialog |
| `Cmd/Ctrl + W` | Close current tab |

## Configuration

Config is auto-saved to platform-specific directories:

- **Linux:** `~/.config/cer-viewer/config.json`
- **macOS:** `~/Library/Application Support/cer-viewer/config.json`
- **Windows:** `C:\Users\<user>\AppData\Roaming\cer-viewer\config.json`

```json
{
  "theme": "dark",
  "window_width": 1024.0,
  "window_height": 768.0
}
```

## Development

See [AGENTS.md](AGENTS.md) for the developer guide.

```bash
cargo build                                      # Build
cargo test --all-features                        # Test
cargo fmt --all -- --check                       # Format check
cargo clippy --all-targets --all-features -- -D warnings  # Clippy
cargo bench                                      # Benchmarks
```

## License

- [MIT License](LICENSE)
- [Apache License 2.0](LICENSE-APACHE)
