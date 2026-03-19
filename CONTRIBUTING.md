# Contributing to cer-viewer

Thank you for your interest in contributing to cer-viewer! This document provides
guidelines for building, testing, and submitting changes.

## Prerequisites

- [Rust toolchain](https://rustup.rs/) (stable, minimum 1.80)
- For GUI builds: platform-specific dependencies
  - **Linux**: `libgtk-3-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libx11-dev libxi-dev libgl1-mesa-dev`

## Building

```bash
# Build with default features (GUI + CLI)
cargo build --release

# Build with all features
cargo build --release --all-features

# Build without optional features
cargo build --release --no-default-features
```

The compiled binary is placed at `target/release/cer-viewer`.

## Code Style

We use `rustfmt` and `clippy` to enforce a consistent code style.

```bash
# Format code
cargo fmt

# Run clippy (check for warnings/errors)
cargo clippy --all-features

# Run clippy with all warnings treated as errors (CI uses this)
cargo clippy --all-features -- -D warnings
```

Please run `cargo fmt` and fix any `cargo clippy` warnings before submitting a PR.

## Running Tests

```bash
# Run all tests
cargo test

# Run tests with all features enabled
cargo test --all-features

# Run a specific test
cargo test test_parse_pem_certificate_success

# Run benchmarks (only available in dev builds)
cargo bench
```

## Project Structure

```
cer-viewer/
  src/
    cert.rs            # Certificate parsing and field tree
    cert/extensions.rs # X.509 extension parsers (SCT, SAN, etc.)
    cert/chain.rs      # Certificate chain building
    cli.rs             # CLI interface (clap)
    document.rs        # Document abstraction (cert/CSR)
    export/            # PEM/DER export utilities
    formats/           # Format parsers (CSR, PKCS#12, keys)
    validation/        # Chain validation, OCSP, CRL
    ui/                # egui GUI views
    utils/             # Shared utilities
  benches/             # Criterion benchmarks
  tests/               # Integration tests and fixtures
  fuzz/                # Fuzzing targets
```

## Pull Request Process

1. Fork the repository and create a feature branch.
2. Make your changes, ensuring `cargo fmt` and `cargo clippy --all-features` pass cleanly.
3. Add tests for new functionality.
4. Update documentation if applicable.
5. Open a pull request with a clear description of the changes.

### Commit Messages

Use clear, descriptive commit messages. For example:

```
feat: add SCT/CT extension parsing
fix: handle empty PEM blocks gracefully
docs: update CLI examples in README
refactor: extract common formatting utilities
```

## Feature Flags

| Feature          | Description                          |
|------------------|--------------------------------------|
| `network`        | OCSP/CRL fetching via HTTP           |
| `pkcs12`         | PKCS#12 and CMS (PKCS#7) parsing     |
| `private-keys`   | PEM private key parsing (EC, RSA)    |
| `full-formats`   | Enable `pkcs12` + `private-keys`     |
| `default`        | `pkcs12` + `private-keys` + `network`|

## Reporting Issues

When filing a bug report, please include:

- The version of cer-viewer (or commit hash)
- The certificate file that triggers the issue (redact sensitive data if needed)
- The expected behavior vs. actual behavior
- The operating system and Rust version (`rustc --version`)
