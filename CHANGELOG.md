# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-03-19

### Added

#### Certificate Parsing
- PEM and DER certificate parsing via x509-parser
- Collapsible field tree showing all certificate details:
  - Version, Serial Number, Signature Algorithm
  - Issuer and Subject (with per-attribute breakdown)
  - Validity period (Not Before / Not After)
  - Subject Public Key Info (algorithm, key size, public key bytes)
  - X.509 v3 extensions (SAN, Key Usage, Basic Constraints, etc.)
  - Signature Value
  - SHA-256 and SHA-1 fingerprints
- Certificate Transparency (CT) / SCT extension parsing:
  - Log ID, timestamp, signature algorithm, and signature value for each SCT entry
- Full X.509 extension coverage:
  - Subject Alternative Name (SAN)
  - Authority Key Identifier (AKI) and Subject Key Identifier (SKI)
  - Basic Constraints and Key Usage
  - Extended Key Usage (EKU)
  - CRL Distribution Points
  - Authority Information Access (AIA) and Subject Info Access (SIA)
  - Certificate Policies and Policy Mappings
  - Name Constraints
  - Issuer Alternative Name (IAN)
  - Policy Constraints and Inhibit Any Policy
  - NSCertType and NS Comment

#### CSR Support
- PEM and DER CSR (PKCS#10) parsing
- Subject, signature algorithm, and public key display
- CSR extension request parsing
- SHA-256 and SHA-1 fingerprints for CSRs

#### Certificate Chain
- Automatic chain building from leaf to root
- Chain position detection (Leaf, Intermediate, Root)
- Issuer-Subject linkage verification
- Chain completion via AIA CA Issuers download (with `network` feature)
- Cryptographic signature verification on each chain link

#### Validation
- Certificate chain structural validation
- Issuer-Subject DN matching
- CA basic constraint verification
- Self-signed root detection
- Configurable trust store support
- System trust store integration via rustls-native-certs

#### PKCS#12 and Private Keys
- PKCS#12 (.p12/.pfx) file parsing (with `pkcs12` feature)
- CMS/PKCS#7 signed data parsing (with `pkcs12` feature)
- PEM private key parsing for EC, RSA, and PKCS#8 formats (with `private-keys` feature)

#### CLI Interface
- File loading (PEM, DER, CSR, PKCS#12)
- JSON output format (`--format json`)
- `chain` subcommand for certificate chain display
- `extract` subcommand for field extraction
- `verify` subcommand for certificate verification
- `convert` subcommand for PEM/DER format conversion
- Colored terminal output

#### GUI
- Modern dark theme powered by egui/eframe
- Native file-open dialog
- Copy any field value to the clipboard
- Multiple certificate tab support
- Certificate chain view panel
- Keyboard shortcuts

#### PEM/DER Conversion
- Bidirectional PEM to DER conversion
- Auto-detection of DER object type (certificate, CSR, private key)
- PEM chain export (multiple certificates)

#### Documentation & Tooling
- Criterion performance benchmarks
- Fuzzing targets
- Comprehensive test suite
- CLA assistant integration
