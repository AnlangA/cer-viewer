# cer-viewer

A modern X.509 certificate viewer built with [egui](https://github.com/emilk/egui)/[eframe](https://github.com/emilk/egui/tree/master/crates/eframe).

Supports PEM and DER encoded certificates with a collapsible field tree, dark theme, and a native file-open dialog.

## 📦 Downloads

Pre-built binaries for Windows, macOS, and Linux are available on the **[Releases page](https://github.com/AnlangA/cer-viewer/releases)**.

## Features

- Open PEM (`.pem`, `.crt`) and DER (`.cer`, `.der`) certificate files via a file dialog
- Collapsible field tree showing all certificate details:
  - Version, Serial Number, Signature Algorithm
  - Issuer and Subject (with per-attribute breakdown)
  - Validity period (Not Before / Not After)
  - Subject Public Key Info (algorithm, key size, public key bytes)
  - X.509 v3 extensions (SAN, Key Usage, Basic Constraints, etc.)
  - Signature Value
  - SHA-256 and SHA-1 fingerprints
- Dark theme powered by egui
- Copy any field value to the clipboard

## Building from Source

**Prerequisites:** [Rust toolchain](https://rustup.rs/) (stable)

```bash
git clone https://github.com/AnlangA/cer-viewer.git
cd cer-viewer
cargo build --release
```

The compiled binary is placed at `target/release/cer-viewer` (or `cer-viewer.exe` on Windows).

### Linux additional dependencies

```bash
sudo apt-get install -y libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev \
  libxcb-xfixes0-dev libx11-dev libxi-dev libgl1-mesa-dev
```

## Usage

Run the binary and use the **Open Certificate** button to load a `.pem`, `.crt`, `.cer`, or `.der` file.

## License

This project is distributed under the terms of the MIT license.
