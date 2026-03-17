# Fuzz Testing

This directory contains fuzz tests for cer-viewer using `cargo-fuzz`.

## Prerequisites

Install nightly Rust and cargo-fuzz:

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Running Fuzz Tests

Run all fuzz targets for a few seconds:

```bash
cargo fuzz run -s release certificate_parsing
cargo fuzz run -s release asn1_parsing
cargo fuzz run -s release crl_parsing
```

Run fuzzers for a longer duration:

```bash
cargo fuzz run certificate_parsing -- -max_total_time=3600
```

## Fuzz Targets

### certificate_parsing
Tests certificate parsing (PEM/DER) with arbitrary input.

### asn1_parsing
Tests ASN.1 DER parsing with arbitrary input.

### crl_parsing
Tests CRL (Certificate Revocation List) parsing with arbitrary input.

## Adding New Fuzz Targets

1. Create a new file in `fuzz_targets/`
2. Add it to `fuzz/Cargo.toml`
3. Use the `fuzz_target!` macro

Example:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Your fuzz test code here
});
```

## CI Integration

Fuzz tests are run in CI on pushes to main branch using a sanity check
configuration. The CI results are collected but won't cause build failures.
