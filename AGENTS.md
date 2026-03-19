# cer-viewer - Developer Guide

## Project Overview

cer-viewer is a modern X.509 certificate and CSR viewer written in Rust. GUI is built with egui/eframe; CLI mode is provided via clap.

- **Version**: v1.2.1 (git tag) / `0.1.0` (crate)
- **License**: MIT OR Apache-2.0
- **Min Rust**: 1.80
- **Stack**: egui 0.33.3, x509-parser 0.18.1, rcgen 0.14.7, clap 4.5, reqwest 0.12, thiserror 2.0, serde, zeroize + secrecy

## Architecture

```
main.rs
├── CLI args → cli::run() → exit
└── No args  → GUI (eframe::run_native)
                  │
              CertViewerApp (ui/)
              ├─ toolbar, tab_bar, details_view
              ├─ chain_view, diff_view, field_tree
              ├─ generate_dialog, password_dialog
              └─ empty_state
                  │
              document::Document  (Certificate | Csr)
                  │
          ┌───────┴───────┐
      cert::ParsedCert   formats/
      cert::CertField     ├─ x509 (re-exports cert)
      cert::CertChain     ├─ csr  (ParsedCsr)
                          ├─ keys (private-keys feat)
                          ├─ pkcs12 (pkcs12 feat)
                          ├─ cms  (pkcs12 feat)
                          └─ asn1 (ASN.1 viewer)
```

**Data flow:** File load → format detection → PEM/DER parse → Document wrap → UI/CLI render

## Module Structure

```
src/
├── main.rs              # Entry point, tracing init, CLI/GUI dispatch
├── lib.rs               # Library entry, public module exports
├── cli.rs               # CLI definition (clap derive) and all subcommand handlers
├── config.rs            # Config persistence (theme, window size), JSON format
├── theme.rs             # Dark/light theme constants, egui Visuals config
├── cert.rs              # Core types: ParsedCert, CertField, ValidityStatus, CertId
├── document.rs          # Document enum (Certificate/Csr), load_documents() entry
├── cert/
│   ├── chain.rs         # CertChain, ChainCert, ChainPosition, signature verification
│   ├── chain_cache.rs   # Disk cache for downloaded intermediate CA certs
│   ├── extensions.rs    # 18 X.509 extension parsers (SAN, SKI, AKI, BC, KU, etc.)
│   ├── format.rs        # File format detection: detect_format()
│   └── error.rs         # CertError enum, Result<T> alias
├── formats/
│   ├── mod.rs           # Format module entry (feature-gated)
│   ├── x509.rs          # Re-exports cert module public API
│   ├── csr.rs           # PKCS#10 CSR parsing: ParsedCsr, CsrId
│   ├── keys.rs          # Private key parsing: KeyType, ParsedPrivateKey (private-keys)
│   ├── pkcs12.rs        # PKCS#12 basic structure parsing (pkcs12)
│   ├── cms.rs           # CMS/PKCS#7 certificate chain extraction (pkcs12)
│   └── asn1.rs          # ASN.1 DER structure viewer, tag parsing, OID lookup
├── export/
│   └── mod.rs           # PEM/DER export, chain export, pem_to_der conversion
├── generation/
│   ├── mod.rs           # Generation module entry
│   ├── self_signed.rs   # Self-signed cert: SelfSignedParams, GeneratedCert
│   └── csr_gen.rs       # CSR generation: CsrParams, GeneratedCsr
├── validation/
│   ├── mod.rs           # Validation module entry
│   ├── chain.rs         # ChainValidator: system trust-based chain validation
│   ├── verifier.rs      # Verifier: comprehensive verification report
│   ├── ocsp.rs          # OCSP response parsing (basic framework)
│   ├── crl.rs           # CRL parsing (basic framework)
│   └── revocation.rs    # RevocationStatus enum
├── security/
│   ├── mod.rs           # Security module entry
│   ├── protected.rs     # ProtectedString: zeroize-protected sensitive strings
│   └── sensitive.rs     # Sensitive data detection, classification, copy warnings
├── utils/
│   ├── mod.rs           # Utility entry: bytes_contains(), bytes_contains_any()
│   ├── base64.rs        # Hex/Base64 encoding/decoding utilities
│   ├── oid.rs           # OID registry: describe_oid(), global OID_REGISTRY
│   └── time.rs          # Time formatting utilities
└── ui/
    ├── mod.rs           # UI module entry, exports CertViewerApp
    ├── app.rs           # Main app state, eframe::App impl
    ├── toolbar.rs       # Toolbar: open file, chain view, theme, generate
    ├── tab_bar.rs       # Multi-document tab bar, CSR/leaf indicators
    ├── details_view.rs  # Certificate detail panel, validity banner
    ├── chain_view.rs    # Chain panel: hierarchical display, signature status
    ├── diff_view.rs     # Two-document field diff comparison
    ├── field_tree.rs    # Recursive collapsible CertField tree renderer
    ├── empty_state.rs   # Welcome screen when no documents are open
    ├── generate_dialog.rs  # Self-signed cert/CSR parameter form
    └── password_dialog.rs  # PKCS#12 password input (reserved)

tests/
├── cli_tests.rs         # CLI subcommand integration tests
├── fixture_tests.rs     # Fixture-based certificate loading tests
└── integration_tests.rs # End-to-end integration tests

benches/
└── parsing.rs           # Criterion benchmarks
```

## Feature Flags

| Feature | Effect | Dependencies |
|---------|--------|-------------|
| `network` | OCSP/CRL checks, AIA chain completion | `reqwest` (blocking), `tokio` (rt) |
| `pkcs12` | PKCS#12 (.p12/.pfx) and CMS/PKCS#7 (.p7b) parsing | `pkcs12` v0.2.0-pre.0 |
| `private-keys` | Private key parsing (PKCS#8, SEC1 EC, RSA PKCS#1) | `sec1`, `spki`, `pkcs8` |
| `full-formats` | All format support (`pkcs12` + `private-keys`) | Both above |

**Default**: `["pkcs12", "private-keys", "network"]`
**Minimal build**: `cargo build --no-default-features` (X.509 PEM/DER + CSR only)

## Core Data Types

### ParsedCert (`src/cert.rs`)

| Field | Type | Purpose |
|-------|------|---------|
| `id` | `CertId` | Unique identifier (SHA-256 fingerprint) |
| `display_name` | `String` | Display name (usually CN) |
| `serial_number` | `String` | Colon-separated hex serial |
| `sha256_fingerprint` | `String` | SHA-256 fingerprint |
| `sha1_fingerprint` | `String` | SHA-1 fingerprint |
| `validity_status` | `ValidityStatus` | Current validity state |
| `not_before` / `not_after` | `String` | Validity period (UTC) |
| `issuer` / `subject` | `String` | Issuer/Subject DN |
| `fields` | `Vec<CertField>` | Root-level field tree |
| `raw_der` | `Vec<u8>` | Raw DER bytes for export |

**Methods:** `to_pem() -> String`

### ParsedCsr (`src/formats/csr.rs`)

Similar structure with `subject`, `signature_algorithm`, `fields`, `raw_der`.

### CertField (`src/cert.rs`)

| Field | Type | Purpose |
|-------|------|---------|
| `label` | `String` | Field label |
| `value` | `Option<String>` | Leaf node value; `None` for containers |
| `children` | `Vec<CertField>` | Child fields |

**Constructors:** `CertField::leaf(label, value)`, `CertField::container(label, children)`, `CertField::node(label, value, children)`

### Document (`src/document.rs`)

```rust
pub enum Document {
    Certificate(ParsedCert),
    Csr(ParsedCsr),
}
```

**Methods:** `display_name()`, `fields()`, `id_str()`, `is_csr()`, `raw_der()`, `to_pem()`, `subject()`

### Key Enums

- `ChainPosition`: `Leaf`, `Intermediate { depth }`, `Root`
- `ChainValidationStatus`: `Valid`, `Incomplete { missing_count }`, `BrokenLinks`, `Empty`
- `SignatureStatus`: `Valid`, `Invalid`, `Unknown`
- `ValidityStatus`: `Valid`, `NotYetValid`, `Expired`
- `FileFormat`: `Pem`, `Der`, `Pkcs12`, `Cms`, `Unknown`

## Key APIs

### Parsing

```rust
cert::parse_pem_certificate(data: &[u8]) -> Result<ParsedCert>
cert::parse_pem_certificates(data: &[u8]) -> Vec<Result<ParsedCert>>
cert::parse_der_certificate(data: &[u8]) -> Result<ParsedCert>
cert::parse_certificate(data: &[u8]) -> Result<ParsedCert>
cert::parse_certificates(data: &[u8]) -> Vec<Result<ParsedCert>>
formats::csr::parse_csr_pem(data: &[u8]) -> Result<ParsedCsr>
formats::csr::parse_csr_der(data: &[u8]) -> Result<ParsedCsr>
document::load_documents(data: &[u8]) -> Vec<Result<Document, String>>
```

### Chain

```rust
CertChain::build(certs: Vec<ParsedCert>) -> CertChain
CertChain::complete_chain(self) -> Self                    // network feature
cert::chain_cache::ChainCache::new() -> ChainCache
```

### Export & Generation

```rust
export::to_pem(label, data) -> String
export::pem_to_der(pem_data) -> Result<Vec<u8>>
export::export_chain_as_pem(certs) -> String
generation::self_signed::generate_self_signed_cert(params) -> Result<GeneratedCert>
generation::csr_gen::generate_csr(params) -> Result<GeneratedCsr>
```

### Validation

```rust
validation::chain::ChainValidator::with_system_trust() -> ChainValidator
validation::verifier::Verifier::new() -> Verifier
```

### Format Detection

```rust
cert::format::detect_format(data: &[u8]) -> FileFormat
cert::format::is_pem_certificate(data: &[u8]) -> bool
cert::format::is_pem_private_key(data: &[u8]) -> bool
```

## CLI Interface

```
cer-viewer [OPTIONS] [FILES]... [COMMAND]

Options:
  -f, --format <FORMAT>   Output: text | json | table (default: text)
  -c, --chain             Show as chain view
  --fields <FIELDS>       Show only specific fields (comma-separated)
  --no-color              Disable colored output

Commands:
  chain <FILES>...              Certificate chain display
  extract <FILE> <FIELD>        Extract specific field
    Cert: subject, issuer, serial, sha256, sha1, not_before, not_after, name, pem
    CSR:  subject, sha256, sha1, signature, pem
  verify <FILES>...             Verify certificate validity
    --trust-store <FILE>        Custom trust store
    --hostname <HOST>           Hostname verification
  convert <INPUT> <OUTPUT> --to <FORMAT>   PEM <-> DER conversion
  fingerprint <FILES>...        SHA-256 and SHA-1 fingerprints
  cache <COMMAND>               Cache management
    list | clear | info | cleanup [DAYS]
```

## UI Architecture

### ViewMode

```rust
pub(crate) enum ViewMode { Details, Chain }
```

### UI Module Responsibilities

| Module | File | Role |
|--------|------|------|
| `app` | `app.rs` | `CertViewerApp` state, `eframe::App` impl, file loading, tab/theme management |
| `toolbar` | `toolbar.rs` | Top bar: open file, view mode toggle, theme, generate buttons, shortcuts |
| `tab_bar` | `tab_bar.rs` | Multi-document tabs, close, CSR blue indicator, leaf gold indicator |
| `details_view` | `details_view.rs` | Detail panel: validity banner (green/yellow/red), field tree, copy button |
| `chain_view` | `chain_view.rs` | Chain panel: leaf/intermediate/root hierarchy, signature status |
| `diff_view` | `diff_view.rs` | Two-document diff: green/red field difference annotations |
| `field_tree` | `field_tree.rs` | Recursive collapsible tree: expand/collapse, copy value, sensitive warning |
| `generate_dialog` | `generate_dialog.rs` | Generation form: CN, SAN, key type/size, validity period |
| `password_dialog` | `password_dialog.rs` | PKCS#12 password input (reserved) |
| `empty_state` | `empty_state.rs` | Welcome screen: drag hint, keyboard shortcuts |

### Theme System (`src/theme.rs`)

- `ThemeMode`: `Dark` (default), `Light`
- Per-theme color constants: `BG_PRIMARY`, `TEXT_PRIMARY`, `ACCENT`, `BORDER`, etc.
- Status colors: `STATUS_VALID` (green), `STATUS_NOT_YET_VALID` (yellow), `STATUS_EXPIRED` (red)
- Indicators: `LEAF_INDICATOR` (gold), `CSR_INDICATOR` (blue)
- Helpers: `validity_color(status)`, `validity_text(status)`, `apply_theme(ctx, mode)`

## Code Conventions

### Naming

- Types: `PascalCase` (`ParsedCert`, `CertField`)
- Functions: `snake_case` (`parse_pem_certificate`)
- Constants: `UPPER_SNAKE_CASE` (`BG_PRIMARY`, `FONT_BODY`)
- Module-internal: `pub(crate)` or private

### Error Handling

- Core error: `cert::CertError` (thiserror-derived)
- Variants: `PemParse`, `DerParse`, `FileRead`, `Clipboard`, `Validation`, `UnsupportedFormat`, `NoCertificate`
- Helpers: `CertError::pem(msg)`, `CertError::der(msg)`, `CertError::parse(msg)`
- Result alias: `cert::Result<T> = std::result::Result<T, CertError>`
- CLI top-level: `Result<bool, String>` with `eprintln!` reporting
- Validation module: independent error types (`OcspError`, `CrlError`)

### Testing

- Unit tests: 216 (via `cargo test --lib --all-features`)
- Integration tests: 8 (via `cargo test --tests --all-features`)
- Fixtures: `assets/` and `tests/fixtures/certificates/{valid,invalid}/`
- Test naming: `test_<module>_<scenario>`
- Benchmarks: `benches/parsing.rs` (criterion)

## Build & Test

```bash
cargo build                                      # Default (all features)
cargo build --no-default-features                # Minimal
cargo build --no-default-features --features full-formats  # Formats, no network
cargo test --all-features                        # All tests
cargo test --lib --all-features                  # Unit tests only
cargo test --tests --all-features                # Integration tests only
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo bench
```

### Release Profiles

- `release`: `opt-level=3`, `lto=true`, `codegen-units=1`, `strip=true`, `panic=abort`
- `release-small`: `opt-level="s"`, `lto="fat"`, `strip=true`

## Known Limitations

1. **PKCS#12**: The `pkcs12` crate (v0.2.0-pre.0) is pre-release. Password-protected PKCS#12 decryption is not yet supported. Only unencrypted PFX structures can be parsed. See `src/formats/pkcs12.rs`.

2. **OCSP/CRL**: `src/validation/ocsp.rs` and `src/validation/crl.rs` contain basic frameworks with mock data. Full OCSP request construction and CRL parsing are not implemented.

3. **ASN.1**: `src/formats/asn1.rs` provides basic structure viewing but limited deep content decoding.

4. **Key material**: `ParsedPrivateKey` in `src/formats/keys.rs` only stores key metadata (type, size), not actual key material, to prevent accidental leakage.

5. **Protected paths**: Not all sensitive data paths currently use `ProtectedString`.
