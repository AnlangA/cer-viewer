# cer-viewer

A modern X.509 certificate viewer built with [egui](https://github.com/emilk/egui)/[eframe](https://github.com/emilk/egui/tree/master/crates/eframe), supporting both GUI and CLI modes.

[中文文档](README.md) | English

[![CI](https://github.com/AnlangA/cer-viewer/actions/workflows/ci.yml/badge.svg)](https://github.com/AnlangA/cer-viewer/actions)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust 1.80+](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)

## Features

### Certificate & CSR Viewing
- PEM (`.pem`, `.crt`) and DER (`.cer`, `.der`) X.509 certificate parsing
- CSR (PKCS#10) file support (`.csr`, `.p10`) with extension attribute parsing
- Collapsible field tree displaying all certificate details: version, serial number, signature algorithm, issuer, subject, validity, public key info, extensions, signature value, fingerprints
- 18 X.509 v3 extensions: SAN, Key Usage, Basic Constraints, EKU, AIA, CRL Distribution Points, Certificate Policies, SCT/CT, Name Constraints, Policy Mappings, Policy Constraints, Inhibit Any Policy, Subject Info Access, Issuer Alternative Name, NS Cert Type, etc.
- SHA-256 and SHA-1 fingerprint calculation and display

### Certificate Chain
- Automatic certificate chain building from leaf to root CA
- Automatic intermediate certificate download via AIA CA Issuers
- Cryptographic signature verification (requires `network` feature)
- Issuer-Subject chain validation and integrity checking
- System trust store integration

### CLI Tools
- View detailed certificate and CSR information
- JSON output format for script integration
- Subcommands: `view`, `chain`, `extract`, `verify`, `convert`, `fingerprint`, `cache`
- Pipe/Stdin input support
- Colored output (can be disabled)

### GUI Features
- Dark/light theme switching with modern color scheme
- Multi-tab support for opening multiple certificates and CSRs simultaneously
- Collapsible certificate field tree
- One-click field value copying to clipboard
- Recent files list
- Certificate comparison view
- Certificate chain visualization
- Certificate generation dialog (self-signed certificates and CSRs)
- PKCS#12 password input dialog
- Sensitive data detection and security warnings

### Security Features
- Automatic sensitive data detection (private keys, passwords, key materials)
- Security warnings when copying sensitive data
- `ProtectedString` type with `zeroize` for automatic memory erasure
- Password-protected PKCS#12 file detection support

### Certificate Generation Tools
- Self-signed certificate generation (RSA 2048/3072/4096, EC P-256/P-384/P-521)
- CSR (Certificate Signing Request) generation
- Subject Alternative Names support (DNS names and IP addresses)
- CA certificate generation support
- PEM and DER output formats

## Screenshots

The GUI mode provides a modern certificate viewing interface with toolbar, multi-tab support, collapsible field trees, and certificate chain visualization. Dark and light themes are supported.

## Supported Formats

| Format | Extension | Description | Feature |
|--------|-----------|-------------|---------|
| X.509 Certificate (PEM) | `.pem`, `.crt` | Base64 encoded with BEGIN/END markers | Default |
| X.509 Certificate (DER) | `.cer`, `.der` | Binary ASN.1 encoding | Default |
| CSR / PKCS#10 | `.csr`, `.p10` | Certificate Signing Request | Default |
| PKCS#12 / PFX | `.p12`, `.pfx` | Certificate and private key bundle | `pkcs12` |
| CMS / PKCS#7 | `.p7b`, `.p7c` | Signed data (certificate chain) | `pkcs12` |
| Private Key (PKCS#8) | `.key`, `.pem` | General private key format | `private-keys` |
| Private Key (EC/SEC1) | `.key`, `.pem` | EC elliptic curve private key | `private-keys` |
| Private Key (RSA/PKCS#1) | `.key`, `.pem` | RSA traditional private key format | `private-keys` |

## Installation

### Pre-built Binaries

Pre-built binaries are available on the [Releases page](https://github.com/AnlangA/cer-viewer/releases) for the following platforms:

- Windows (x86_64)
- macOS (Apple Silicon / Intel)
- Linux (x86_64)

### Building from Source

**Prerequisites:** [Rust toolchain](https://rustup.rs/) (stable, minimum 1.80)

```bash
git clone https://github.com/AnlangA/cer-viewer.git
cd cer-viewer
cargo build --release
```

The compiled binary is located at `target/release/cer-viewer` (or `cer-viewer.exe` on Windows).

#### Feature Flags

```bash
# Default build (all features enabled)
cargo build --release

# Minimal build (no network or private key parsing)
cargo build --release --no-default-features

# All format support
cargo build --release --features full-formats

# Network features only (OCSP/CRL)
cargo build --release --features network
```

| Feature | Description | Default |
|---------|-------------|---------|
| `pkcs12` | PKCS#12 and CMS/PKCS#7 parsing | Enabled |
| `private-keys` | Private key parsing (PKCS#8, EC, RSA) | Enabled |
| `network` | Network operations (OCSP/CRL, chain completion) | Enabled |
| `full-formats` | All format support (`pkcs12` + `private-keys`) | -- |

#### Linux Additional Dependencies

```bash
sudo apt-get install -y libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libx11-dev libxi-dev libgl1-mesa-dev
```

### System Requirements

- **Rust:** 1.80 or higher
- **Platforms:** Windows, macOS, Linux (requires GTK3)

## Usage

### GUI Mode

Run the binary without arguments to start the graphical interface:

```bash
cer-viewer
```

Operation instructions:
- Click **Open Files...** button or use keyboard shortcut to open file dialog
- Drag and drop files to the window to open
- Open multiple files simultaneously with tabbed display
- Click fields in the tree to copy values to clipboard
- Right-click on tabs to close other tabs or close tabs to the right
- Click the theme icon in the toolbar to switch between dark and light themes

### CLI Mode

Provide file paths to enter CLI mode for certificate information viewing:

```bash
# View certificate
cer-viewer certificate.pem

# JSON output format
cer-viewer --format json certificate.pem

# Table output format
cer-viewer --format table certificate.pem

# Show only specific fields
cer-viewer --fields subject,issuer certificate.pem

# View multiple certificates with chain info
cer-viewer --chain leaf.crt intermediate.crt root.crt

# Read from stdin
cat certificate.pem | cer-viewer -
```

#### Subcommands

**view -- View Certificate/CSR**

```bash
cer-viewer certificate.pem
cer-viewer --format json certificate.pem
cer-viewer --fields subject,issuer,serial certificate.pem
cer-viewer --no-color certificate.pem
```

**chain -- Certificate Chain Analysis**

```bash
# Analyze certificate chain
cer-viewer chain leaf.crt intermediate.crt root.crt

# Table format display
cer-viewer chain --format table leaf.crt intermediate.crt root.crt

# JSON format output
cer-viewer chain --format json leaf.crt intermediate.crt root.crt
```

**extract -- Extract Specific Fields**

```bash
# Extract certificate fields
cer-viewer extract certificate.pem subject
cer-viewer extract certificate.pem issuer
cer-viewer extract certificate.pem serial
cer-viewer extract certificate.pem sha256
cer-viewer extract certificate.pem sha1
cer-viewer extract certificate.pem not_before
cer-viewer extract certificate.pem not_after
cer-viewer extract certificate.pem name
cer-viewer extract certificate.pem pem

# Extract CSR fields
cer-viewer extract request.csr subject
cer-viewer extract request.csr signature
cer-viewer extract request.csr fingerprint
```

**verify -- Verify Certificate**

```bash
# Verify single certificate
cer-viewer verify certificate.pem

# Verify certificate chain
cer-viewer verify leaf.crt intermediate.crt root.crt
```

**convert -- Format Conversion**

```bash
# PEM to DER
cer-viewer convert input.pem output.der --to der

# DER to PEM
cer-viewer convert input.der output.pem --to pem
```

**fingerprint -- Show Fingerprints**

```bash
# Show SHA-256 and SHA-1 fingerprints
cer-viewer fingerprint certificate.pem

# Show fingerprints for multiple certificates
cer-viewer fingerprint cert1.pem cert2.pem
```

**cache -- Cache Management**

```bash
# View cache info
cer-viewer cache info

# List all cache entries
cer-viewer cache list

# Clean cache older than 30 days
cer-viewer cache cleanup --days 30

# Clear all cache
cer-viewer cache clear
```

#### Output Formats

| Format | Description |
|--------|-------------|
| `text` | Human-readable text format (default) |
| `json` | JSON format, suitable for script processing |
| `table` | Aligned table format (using comfy-table) |

#### Pipe & Stdin

All commands accepting file paths support reading from stdin using `-`:

```bash
cat certificate.pem | cer-viewer -
cat certificate.pem | cer-viewer extract - subject
cat certificate.pem | cer-viewer --format json -
```

The `colored` library automatically detects if output is piped and disables colored output accordingly. You can also use the `--no-color` global option to force disable colors.

## Keyboard Shortcuts

| Shortcut | Function |
|----------|----------|
| `Cmd/Ctrl + O` | Open file dialog |
| `Cmd/Ctrl + W` | Close current tab |

## Configuration

Configuration files are automatically saved to system standard configuration directories:

- **Linux:** `~/.config/cer-viewer/config.json`
- **macOS:** `~/Library/Application Support/cer-viewer/config.json`
- **Windows:** `C:\Users\<user>\AppData\Roaming\cer-viewer\config.json`

Supported configuration items:

```json
{
  "theme": "dark",
  "window_width": 1024.0,
  "window_height": 768.0
}
```

| Config Item | Type | Default | Description |
|-------------|------|---------|-------------|
| `theme` | string | `"dark"` | Theme mode: `dark` or `light` |
| `window_width` | float | `1024.0` | Window width (pixels) |
| `window_height` | float | `768.0` | Window height (pixels) |

## Certificate Chain Cache

When the `network` feature is enabled, the certificate chain completion function automatically caches downloaded certificates to local disk, avoiding duplicate network requests.

Cache mechanism:
- Dual indexing by Subject DN and SHA-256 fingerprint
- Cache content includes certificate DER encoded data
- Stored in system standard cache directories

Cache locations:
- **Linux:** `~/.cache/cer-viewer/`
- **macOS:** `~/Library/Caches/cer-viewer/`
- **Windows:** `C:\Users\<user>\AppData\Local\cache\cer-viewer\`

CLI cache management:

```bash
cer-viewer cache info     # View cache info
cer-viewer cache list     # List cache entries
cer-viewer cache cleanup  # Clean expired cache
cer-viewer cache clear    # Clear all cache
```

## Development

### Project Structure

```
cer-viewer/
├── src/
│   ├── main.rs            # Application entry
│   ├── lib.rs             # Library entry (testing and fuzzing)
│   ├── cli.rs             # CLI command line interface
│   ├── config.rs          # Configuration persistence
│   ├── theme.rs           # Dark/light theme definitions
│   ├── cert.rs            # Certificate parsing and field tree building
│   ├── cert/
│   │   ├── chain.rs       # Certificate chain building and verification
│   │   ├── chain_cache.rs # Certificate chain local cache
│   │   ├── extensions.rs  # X.509 extension parsing
│   │   ├── format.rs      # Format detection
│   │   └── error.rs       # Error type definitions
│   ├── document.rs        # Unified document model (certificate/CSR)
│   ├── formats/
│   │   ├── mod.rs         # Format module entry
│   │   ├── x509.rs        # X.509 format handling
│   │   ├── csr.rs         # CSR/PKCS#10 parsing
│   │   ├── pkcs12.rs      # PKCS#12 parsing
│   │   ├── cms.rs         # CMS/PKCS#7 parsing
│   │   ├── keys.rs        # Private key parsing
│   │   └── asn1.rs        # ASN.1 utilities
│   ├── export/
│   │   └── mod.rs         # PEM/DER export and conversion
│   ├── generation/
│   │   ├── mod.rs         # Certificate generation module entry
│   │   ├── self_signed.rs # Self-signed certificate generation
│   │   └── csr_gen.rs     # CSR generation
│   ├── validation/
│   │   ├── mod.rs         # Validation module entry
│   │   ├── chain.rs       # Chain validation
│   │   ├── ocsp.rs        # OCSP checking
│   │   ├── crl.rs         # CRL checking
│   │   └── revocation.rs  # Revocation status checking
│   ├── security/
│   │   ├── mod.rs         # Security module entry
│   │   ├── protected.rs   # ProtectedString (auto-erase)
│   │   └── sensitive.rs   # Sensitive data detection
│   ├── ui/
│   │   ├── mod.rs         # UI module entry
│   │   ├── app.rs         # Main application state and logic
│   │   ├── toolbar.rs     # Toolbar and tabs
│   │   ├── tab_bar.rs     # Tab management
│   │   ├── details_view.rs # Certificate details view
│   │   ├── field_tree.rs  # Collapsible field tree
│   │   ├── chain_view.rs  # Certificate chain view
│   │   ├── diff_view.rs   # Certificate comparison view
│   │   ├── generate_dialog.rs  # Certificate generation dialog
│   │   ├── password_dialog.rs  # Password input dialog
│   │   └── empty_state.rs # Empty state prompt
│   └── utils/
│       └── mod.rs         # Common utility functions
├── tests/
│   ├── cli_tests.rs       # CLI integration tests
│   ├── fixture_tests.rs   # Fixture tests
│   └── integration_tests.rs # Integration tests
├── benches/
│   └── parsing.rs         # Criterion benchmarks
├── assets/                # Test certificate and CSR files
└── .github/workflows/
    └── ci.yml             # CI configuration
```

### Building and Testing

```bash
# Build
cargo build

# Run tests
cargo test

# Run tests with all features
cargo test --all-features

# Run tests (without network feature)
cargo test

# Code format check
cargo fmt --all -- --check

# Code formatting
cargo fmt --all

# Clippy static analysis
cargo clippy --all-targets --all-features -- -D warnings

# Benchmarks
cargo bench
```

The CI pipeline automatically runs format checks, Clippy, tests (with all features and without network feature), and generates code coverage reports on every commit.

### Code Standards

Please refer to [AGENTS.md](AGENTS.md) for detailed development guidelines.

## License

This project is dual-licensed:

- [MIT License](LICENSE)
- [Apache License 2.0](LICENSE-APACHE)
