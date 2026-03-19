//! Certificate chain validation.
//!
//! Validates that a chain of DER-encoded certificates forms a proper issuer/subject
//! path, that intermediate certificates carry the CA basic constraint, and that the
//! chain terminates at a self-signed root (or a certificate present in a configured
//! trust store).

#![allow(dead_code)] // Public API – used by validation callers and tests

use crate::cert::{CertError, Result};
use x509_parser::prelude::*;

/// Certificate chain validator.
pub struct ChainValidator {
    /// Trusted root certificates (DER-encoded).
    ///
    /// When non-empty the chain's last certificate must appear in this list.
    /// When empty the validator accepts any self-signed root.
    trusted_roots: Vec<Vec<u8>>,
}

impl ChainValidator {
    /// Create a new validator that loads the OS-native root certificate store.
    ///
    /// Uses `rustls_native_certs::load_native_certs()` to read the system's
    /// trusted CA bundle (e.g. `/etc/ssl/certs` on Linux, the Keychain on
    /// macOS, the system certificate store on Windows).
    ///
    /// If loading the system store fails the error is logged and an empty
    /// store is used, so validation falls back to accepting any self-signed
    /// root.
    pub fn with_system_trust() -> Self {
        let result = rustls_native_certs::load_native_certs();
        if !result.certs.is_empty() {
            tracing::info!("Loaded {} system root certificates", result.certs.len());
        }
        if !result.errors.is_empty() {
            tracing::warn!(
                "Errors while loading system root certificates: {:?}",
                result.errors
            );
        }
        Self {
            trusted_roots: result.certs.into_iter().map(|c| c.to_vec()).collect(),
        }
    }

    /// Create a new validator that only accepts roots present in `roots`.
    pub fn with_trusted_roots(roots: Vec<Vec<u8>>) -> Self {
        Self {
            trusted_roots: roots,
        }
    }

    /// Validate a certificate chain supplied as a slice of DER-encoded bytes.
    ///
    /// The slice must be ordered from the **leaf** (index 0) to the **root**
    /// (last index).  An empty slice is considered valid.
    ///
    /// Validation checks, in order:
    /// 1. Every certificate can be parsed.
    /// 2. For each consecutive pair `(cert[i], cert[i+1])` the issuer DN of
    ///    `cert[i]` equals the subject DN of `cert[i+1]`.
    /// 3. Every certificate other than the leaf carries `BasicConstraints(isCA=true)`.
    /// 4. The last certificate is self-signed **or** present in the trusted-root
    ///    store (when one is configured).
    pub fn validate(&self, chain: &[Vec<u8>]) -> Result<ValidationResult> {
        if chain.is_empty() {
            return Ok(ValidationResult::Valid);
        }

        // Step 1: parse all certificates.
        // The raw DER slices must stay alive so parsed structs can borrow from them.
        let parsed_result: std::result::Result<Vec<X509Certificate<'_>>, _> = chain
            .iter()
            .map(|der| {
                X509Certificate::from_der(der)
                    .map(|(_, cert)| cert)
                    .map_err(|e| CertError::der(format!("Failed to parse certificate: {e}")))
            })
            .collect();

        let parsed = match parsed_result {
            Ok(certs) => certs,
            Err(e) => return Ok(ValidationResult::Invalid(e.to_string())),
        };

        // Step 2: check issuer → subject linkage for each consecutive pair.
        for i in 0..parsed.len().saturating_sub(1) {
            let subject_cert = &parsed[i];
            let issuer_cert = &parsed[i + 1];

            if subject_cert.issuer() != issuer_cert.subject() {
                return Ok(ValidationResult::Invalid(format!(
                    "Chain is broken between certificate {} and {}: \
                     issuer '{}' does not match subject '{}'",
                    i,
                    i + 1,
                    subject_cert.issuer(),
                    issuer_cert.subject(),
                )));
            }
        }

        // Step 3: every non-leaf certificate must have CA basic constraints.
        for (i, cert) in parsed.iter().enumerate().skip(1) {
            let is_ca = cert
                .basic_constraints()
                .ok()
                .flatten()
                .map(|bc| bc.value.ca)
                .unwrap_or(false);

            if !is_ca {
                return Ok(ValidationResult::Invalid(format!(
                    "Certificate {} ('{}') is not a CA but appears as an issuer in the chain",
                    i,
                    cert.subject(),
                )));
            }
        }

        // Step 4: the root must be self-signed or in the trust store.
        let root = parsed.last().unwrap();
        let root_der = chain.last().unwrap();
        let is_self_signed = root.issuer() == root.subject();

        if !self.trusted_roots.is_empty() {
            // Trust-store mode: root must be present.
            if !self.trusted_roots.contains(root_der) {
                return Ok(ValidationResult::Invalid(
                    "The chain's root certificate is not present in the trusted root store"
                        .to_string(),
                ));
            }
        } else if !is_self_signed {
            // No trust store: we can't confirm the root is trusted.
            return Ok(ValidationResult::Unknown(
                "Chain does not terminate at a self-signed root and no trust store is configured"
                    .to_string(),
            ));
        }

        Ok(ValidationResult::Valid)
    }
}

/// Result of certificate chain validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Chain is structurally valid and the root is trusted.
    Valid,
    /// Chain has a structural error (broken link, non-CA issuer, untrusted root).
    Invalid(String),
    /// Validation could not be completed (e.g., no trust store and root not self-signed).
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: load a DER certificate from a fixture file (auto-converts PEM → DER).
    fn load_fixture(path: &str) -> Vec<u8> {
        let data =
            std::fs::read(path).unwrap_or_else(|e| panic!("failed to read fixture '{path}': {e}"));
        // Convert PEM → DER if needed.
        if data.starts_with(b"-----") {
            crate::export::pem_to_der(&data)
                .unwrap_or_else(|e| panic!("pem_to_der failed for '{path}': {e}"))
        } else {
            data
        }
    }

    #[test]
    fn test_validator_creation() {
        let validator = ChainValidator::with_system_trust();
        // with_system_trust() loads OS-native root certificates.
        // The list may be empty (CI containers) or contain many certs.
        // We just verify creation succeeds without panicking.
        let _ = &validator.trusted_roots;
    }

    #[test]
    fn test_validate_empty_chain() {
        let validator = ChainValidator::with_system_trust();
        let result = validator.validate(&[]);
        assert!(matches!(result, Ok(ValidationResult::Valid)));
    }

    #[test]
    fn test_validate_invalid_der() {
        let validator = ChainValidator::with_system_trust();
        let result = validator.validate(&[vec![0u8, 1, 2, 3]]);
        // Garbage DER should yield Invalid.
        assert!(matches!(result, Ok(ValidationResult::Invalid(_))));
    }

    #[test]
    fn test_validate_single_self_signed_cert() {
        let root_path = "tests/fixtures/certificates/valid/root ca.crt";
        if !std::path::Path::new(root_path).exists() {
            println!("Skipping: fixture not found");
            return;
        }

        let root_der = load_fixture(root_path);
        // Use with_trusted_roots to include the test root explicitly,
        // since with_system_trust() loads the OS store which won't contain test fixtures.
        let validator = ChainValidator::with_trusted_roots(vec![root_der.clone()]);
        let result = validator.validate(&[root_der]);
        assert!(
            matches!(result, Ok(ValidationResult::Valid)),
            "expected Valid for self-signed root, got: {result:?}"
        );
    }

    /// The fixture intermediate CA is self-signed (issuer == subject), so a 2-cert
    /// chain [leaf, intermediate-as-root] is the longest proper chain we can build
    /// from the existing fixtures.
    #[test]
    fn test_validate_two_cert_chain() {
        let int_path = "tests/fixtures/certificates/valid/intermediate ca.crt";
        let leaf_path = "tests/fixtures/certificates/valid/example.com.crt";

        for path in [int_path, leaf_path] {
            if !std::path::Path::new(path).exists() {
                println!("Skipping: fixture {path} not found");
                return;
            }
        }

        let leaf_der = load_fixture(leaf_path);
        let int_der = load_fixture(int_path);

        // Use with_trusted_roots to include the test intermediate as a trusted root,
        // since with_system_trust() loads the OS store which won't contain test fixtures.
        let validator = ChainValidator::with_trusted_roots(vec![int_der.clone()]);
        // The intermediate CA is self-signed and acts as root here.
        let result = validator.validate(&[leaf_der, int_der]);
        assert!(
            matches!(result, Ok(ValidationResult::Valid)),
            "expected Valid for 2-cert chain, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_trust_store_root_present() {
        let root_path = "tests/fixtures/certificates/valid/root ca.crt";
        if !std::path::Path::new(root_path).exists() {
            println!("Skipping: fixture not found");
            return;
        }

        let root_der = load_fixture(root_path);
        let validator = ChainValidator::with_trusted_roots(vec![root_der.clone()]);
        let result = validator.validate(&[root_der]);
        assert!(matches!(result, Ok(ValidationResult::Valid)));
    }

    #[test]
    fn test_validate_trust_store_root_missing() {
        let root_path = "tests/fixtures/certificates/valid/root ca.crt";
        if !std::path::Path::new(root_path).exists() {
            println!("Skipping: fixture not found");
            return;
        }

        let root_der = load_fixture(root_path);
        // Trust store contains a *different* (empty) set.
        let validator = ChainValidator::with_trusted_roots(vec![vec![0u8; 4]]);
        let result = validator.validate(&[root_der]);
        assert!(matches!(result, Ok(ValidationResult::Invalid(_))));
    }
}
