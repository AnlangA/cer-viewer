# cer-viewer

A modern X.509 certificate viewer built with [egui](https://github.com/emilk/egui)/[eframe](https://github.com/emilk/egui/tree/master/crates/eframe).

Supports PEM and DER encoded certificates with a collapsible field tree, dark theme, and a native file-open dialog.

## Downloads

Pre-built binaries for Windows, macOS, and Linux are available on the **[Releases page](https://github.com/AnlangA/cer-viewer/releases)**.

## Features

### Certificate & CSR Parsing
- Open PEM (`.pem`, `.crt`) and DER (`.cer`, `.der`) certificate files via a file dialog
- CSR (PKCS#10) support (`.csr`, `.p10`)
- PKCS#12 (`.p12`, `.pfx`) and CMS/PKCS#7 signed data parsing
- PEM private key parsing (EC, RSA, PKCS#8)
- Collapsible field tree showing all certificate details:
  - Version, Serial Number, Signature Algorithm
  - Issuer and Subject (with per-attribute breakdown)
  - Validity period (Not Before / Not After)
  - Subject Public Key Info (algorithm, key size, public key bytes)
  - X.509 v3 extensions (SAN, Key Usage, Basic Constraints, EKU, AIA, CRL Distribution Points, Certificate Policies, SCT/CT, and more)
  - Signature Value
  - SHA-256 and SHA-1 fingerprints

### Certificate Chain
- Automatic chain building from leaf to root CA
- Issuer-Subject linkage verification
- Chain completion via AIA CA Issuers download
- Cryptographic signature verification on each chain link
- System trust store integration

### CLI Interface
- View certificate and CSR details from the terminal
- JSON output format for scripting (`--format json`)
- Subcommands: `chain`, `extract`, `verify`, `convert`

### GUI
- Dark theme powered by egui
- Copy any field value to the clipboard
- Multiple certificate tab support

## Building from Source

**Prerequisites:** [Rust toolchain](https://rustup.rs/) (stable, minimum 1.80)

```bash
git clone https://github.com/AnlangA/cer-viewer.git
cd cer-viewer
cargo build --release
```

The compiled binary is placed at `target/release/cer-viewer` (or `cer-viewer.exe` on Windows).

### Linux additional dependencies

```bash
sudo apt-get install -y libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libx11-dev libxi-dev libgl1-mesa-dev
```

## CLI Examples

```bash
# View a certificate in text mode
cer-viewer certificate.pem

# View in JSON format
cer-viewer --format json certificate.pem

# Show only subject and issuer fields
cer-viewer --fields subject,issuer certificate.pem

# Display certificate chain
cer-viewer chain leaf.crt intermediate.crt root.crt

# Extract a specific field
cer-viewer extract certificate.pem subject
cer-viewer extract certificate.pem sha256

# Verify certificate validity
cer-viewer verify certificate.pem

# Convert between PEM and DER formats
cer-viewer convert input.pem output.der --to der
cer-viewer convert input.der output.pem --to pem
```

## GUI Usage

Run the binary without arguments (or with `--help` to see CLI options) and use the **Open Certificate** button to load a `.pem`, `.crt`, `.cer`, `.der`, `.csr`, or `.p12` file.

### Keyboard Shortcuts

| Shortcut    | Action                            |
|-------------|-----------------------------------|
| `Ctrl+O`    | Open file dialog                  |
| `Ctrl+C`    | Copy selected field value         |
| `Ctrl+W`    | Close current tab                 |
| `Ctrl+Q`    | Quit application                  |
| `F5`        | Refresh / reload current file     |

## License

This project is distributed under the terms of the MIT license.
