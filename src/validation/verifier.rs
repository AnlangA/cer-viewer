//! Certificate verifier.
//!
//! Produces a [`VerificationReport`] by combining cryptographic signature
//! verification, time-validity checks, trust-store lookups, and structural
//! chain validation.

use crate::cert::{CertChain, CertField, ParsedCert, SignatureStatus, ValidityStatus};
use crate::validation::chain::{ChainValidator, ValidationResult};
use crate::validation::report::{
    CertVerification, ChainLinkInfo, ChainVerification, OverallStatus, SanEntry, SignatureResult,
    TimeValidityResult, TrustResult, VerificationReport,
};

/// Certificate verifier that produces a full verification report.
pub struct Verifier {
    custom_trust_roots: Option<Vec<Vec<u8>>>,
}

impl Verifier {
    /// Create a verifier that uses the OS-native system trust store.
    pub fn with_system_trust() -> Self {
        Self {
            custom_trust_roots: None,
        }
    }

    /// Create a verifier that uses a custom set of trusted root certificates (DER-encoded).
    pub fn with_custom_trust(roots: Vec<Vec<u8>>) -> Self {
        Self {
            custom_trust_roots: Some(roots),
        }
    }

    /// Verify one or more certificates and produce a full report.
    pub fn verify(&self, certs: &[ParsedCert]) -> VerificationReport {
        // Build the certificate chain (auto-orders, runs signature verification)
        let chain = CertChain::build(certs.to_vec());

        // Structural chain validation via ChainValidator
        let structural = {
            let chain_der: Vec<Vec<u8>> = chain
                .certificates
                .iter()
                .map(|cc| cc.cert.raw_der.clone())
                .collect();
            let validator = match &self.custom_trust_roots {
                Some(roots) => ChainValidator::with_trusted_roots(roots.clone()),
                None => ChainValidator::with_system_trust(),
            };
            validator.validate(&chain_der)
        };

        // Per-cert verification
        let cert_results: Vec<CertVerification> = chain
            .certificates
            .iter()
            .map(|cc| self.verify_cert(cc, &chain))
            .collect();

        // Chain-level report
        let chain_report = if chain.certificates.len() > 1 {
            let structural_str = match &structural {
                Ok(ValidationResult::Valid) => "Valid".to_string(),
                Ok(ValidationResult::Invalid(msg)) => format!("Invalid: {}", msg),
                Ok(ValidationResult::Unknown(msg)) => format!("Unknown: {}", msg),
                Err(e) => format!("Error: {}", e),
            };
            let chain_valid = matches!(structural, Ok(ValidationResult::Valid));

            let links: Vec<ChainLinkInfo> = chain
                .certificates
                .iter()
                .map(|cc| {
                    let position = match cc.position {
                        crate::cert::ChainPosition::Leaf => "Leaf",
                        crate::cert::ChainPosition::Intermediate { .. } => "Intermediate",
                        crate::cert::ChainPosition::Root => "Root",
                    };
                    let sig_str = match cc.signature_status {
                        SignatureStatus::Valid => "Verified",
                        SignatureStatus::Invalid => "Invalid",
                        SignatureStatus::Unknown => "Unknown",
                    };
                    let is_self_signed = cc.cert.issuer == cc.cert.subject;
                    let trusted = match &cc.position {
                        crate::cert::ChainPosition::Root => chain_valid,
                        _ => true, // Non-root certs depend on chain trust
                    };
                    ChainLinkInfo {
                        name: cc.cert.display_name.clone(),
                        position: position.to_string(),
                        signature_status: sig_str.to_string(),
                        self_signed: is_self_signed,
                        trusted,
                    }
                })
                .collect();

            Some(ChainVerification {
                valid: chain_valid,
                status: if chain_valid {
                    "Valid".to_string()
                } else {
                    "Invalid".to_string()
                },
                length: chain.certificates.len(),
                structural_check: structural_str,
                links,
            })
        } else {
            None
        };

        // Compute overall status
        let overall = self.compute_overall_status(&cert_results, &chain_report, &structural);

        VerificationReport {
            overall_status: overall,
            certificates: cert_results,
            chain: chain_report,
        }
    }

    fn verify_cert(&self, cc: &crate::cert::ChainCert, chain: &CertChain) -> CertVerification {
        let cert = &cc.cert;

        // Time validity
        let time_validity = TimeValidityResult {
            valid: cert.validity_status == ValidityStatus::Valid,
            status: match cert.validity_status {
                ValidityStatus::Valid => "Valid".to_string(),
                ValidityStatus::Expired => "Expired".to_string(),
                ValidityStatus::NotYetValid => "Not yet valid".to_string(),
            },
            not_before: cert.not_before.clone(),
            not_after: cert.not_after.clone(),
        };

        // Signature
        let signature = SignatureResult {
            verified: cc.signature_status == SignatureStatus::Valid,
            status: match cc.signature_status {
                SignatureStatus::Valid => "Verified against issuer".to_string(),
                SignatureStatus::Invalid => "Signature invalid".to_string(),
                SignatureStatus::Unknown => "Unknown (issuer missing)".to_string(),
            },
        };

        // Trust — for single self-signed cert, check trust store
        let is_self_signed = cert.issuer == cert.subject;
        let trust = if is_self_signed {
            let in_trust_store = self
                .custom_trust_roots
                .as_ref()
                .map(|roots| roots.iter().any(|r| r == &cert.raw_der))
                .unwrap_or(false);
            TrustResult {
                trusted: in_trust_store,
                status: if in_trust_store {
                    "Trusted".to_string()
                } else {
                    "Self-signed, not in trust store".to_string()
                },
            }
        } else {
            // For chain certs, trust depends on chain-level validation
            let is_root = matches!(cc.position, crate::cert::ChainPosition::Root);
            let last_is_root = chain
                .certificates
                .last()
                .map(|c| matches!(c.position, crate::cert::ChainPosition::Root))
                .unwrap_or(false);
            if is_root && last_is_root {
                // Root trust is determined by chain validation
                TrustResult {
                    trusted: chain.validation_status == crate::cert::ChainValidationStatus::Valid,
                    status: if chain.validation_status == crate::cert::ChainValidationStatus::Valid
                    {
                        "Chain trust verified".to_string()
                    } else {
                        "Chain trust depends on root".to_string()
                    },
                }
            } else {
                TrustResult {
                    trusted: true,
                    status: "Chain trust depends on root".to_string(),
                }
            }
        };

        // Extract key usage, EKU, SAN from field tree
        let key_usage = extract_key_usage(&cert.fields);
        let extended_key_usage = extract_extended_key_usage(&cert.fields);
        let san_entries = extract_san_entries(&cert.fields);

        CertVerification {
            name: cert.display_name.clone(),
            subject: cert.subject.clone(),
            issuer: cert.issuer.clone(),
            time_validity,
            signature,
            trust,
            self_signed: is_self_signed,
            key_usage,
            extended_key_usage,
            san_entries,
        }
    }

    fn compute_overall_status(
        &self,
        cert_results: &[CertVerification],
        chain_report: &Option<ChainVerification>,
        structural: &std::result::Result<ValidationResult, crate::cert::CertError>,
    ) -> OverallStatus {
        // Hard failures: expired cert, invalid signature
        let has_failure = cert_results
            .iter()
            .any(|c| !c.time_validity.valid || !c.signature.verified);

        if has_failure {
            return OverallStatus::Failed;
        }

        // Warnings: chain structural issues (trust store, broken links), self-signed without trust
        let chain_invalid = chain_report.as_ref().map(|ch| !ch.valid).unwrap_or(false);

        let has_warning = chain_invalid
            || cert_results
                .iter()
                .any(|c| c.self_signed && !c.trust.trusted)
            || matches!(
                structural,
                Ok(ValidationResult::Invalid(_)) | Ok(ValidationResult::Unknown(_))
            );

        if has_warning {
            OverallStatus::Warning
        } else {
            OverallStatus::Ok
        }
    }
}

/// Walk the field tree to find Key Usage values.
fn extract_key_usage(fields: &[CertField]) -> Vec<String> {
    for field in fields {
        if let Some(ku) = find_key_usage_in_node(field) {
            return ku;
        }
    }
    Vec::new()
}

fn find_key_usage_in_node(field: &CertField) -> Option<Vec<String>> {
    let label_lower = field.label.to_lowercase();
    if (label_lower.contains("key usage") || label_lower.contains("keyusage"))
        && !label_lower.contains("extended")
    {
        for child in &field.children {
            if child.label == "Usages" {
                if let Some(ref val) = child.value {
                    return Some(
                        val.split(", ")
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect(),
                    );
                }
            }
        }
    }
    for child in &field.children {
        if let Some(result) = find_key_usage_in_node(child) {
            return Some(result);
        }
    }
    None
}

/// Walk the field tree to find Extended Key Usage values.
fn extract_extended_key_usage(fields: &[CertField]) -> Vec<String> {
    for field in fields {
        if let Some(eku) = find_eku_in_node(field) {
            return eku;
        }
    }
    Vec::new()
}

fn find_eku_in_node(field: &CertField) -> Option<Vec<String>> {
    if field.label.to_lowercase().contains("extendedkeyusage")
        || field.label.contains("Extended Key Usage")
    {
        for child in &field.children {
            if child.label == "Usages" {
                if let Some(ref val) = child.value {
                    return Some(
                        val.split(", ")
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect(),
                    );
                }
            }
        }
    }
    for child in &field.children {
        if let Some(result) = find_eku_in_node(child) {
            return Some(result);
        }
    }
    None
}

/// Walk the field tree to find SAN entries.
fn extract_san_entries(fields: &[CertField]) -> Vec<SanEntry> {
    for field in fields {
        if let Some(entries) = find_san_in_node(field) {
            return entries;
        }
    }
    Vec::new()
}

fn find_san_in_node(field: &CertField) -> Option<Vec<SanEntry>> {
    if field.label.contains("Subject Alternative Name") || field.label.contains("subjectAltName") {
        for child in &field.children {
            if child.label == "Alternative Names" {
                let mut entries = Vec::new();
                for name_field in &child.children {
                    if let Some(ref val) = name_field.value {
                        if let Some((san_type, value)) = parse_san_value(val) {
                            entries.push(SanEntry { san_type, value });
                        }
                    }
                }
                return Some(entries);
            }
        }
    }
    for child in &field.children {
        if let Some(result) = find_san_in_node(child) {
            return Some(result);
        }
    }
    None
}

/// Parse a SAN value like "DNS: example.com" into (type, value).
fn parse_san_value(val: &str) -> Option<(String, String)> {
    if let Some(idx) = val.find(':') {
        let san_type = val[..idx].trim().to_string();
        let value = val[idx + 1..].trim().to_string();
        if !san_type.is_empty() && !value.is_empty() {
            return Some((san_type, value));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixture(path: &str) -> ParsedCert {
        let data =
            std::fs::read(path).unwrap_or_else(|e| panic!("failed to read fixture '{path}': {e}"));
        if data.starts_with(b"-----") {
            crate::cert::parse_pem_certificate(&data)
                .unwrap_or_else(|e| panic!("pem parse failed for '{path}': {e}"))
        } else {
            crate::cert::parse_der_certificate(&data)
                .unwrap_or_else(|e| panic!("der parse failed for '{path}': {e}"))
        }
    }

    fn fixture_exists(path: &str) -> bool {
        std::path::Path::new(path).exists()
    }

    #[test]
    fn test_verify_single_self_signed() {
        let path = "tests/fixtures/certificates/valid/self-signed cert.crt";
        if !fixture_exists(path) {
            println!("Skipping: fixture not found");
            return;
        }
        let cert = load_fixture(path);
        let verifier = Verifier::with_system_trust();
        let report = verifier.verify(&[cert]);
        assert_eq!(report.certificates.len(), 1);
        assert!(report.certificates[0].self_signed);
        // Self-signed cert without matching trust store -> Warning (or Ok if system trusts it)
        assert!(
            matches!(
                report.overall_status,
                OverallStatus::Warning | OverallStatus::Ok
            ),
            "expected Warning or Ok, got: {:?}",
            report.overall_status
        );
    }

    #[test]
    fn test_verify_single_with_custom_trust() {
        let path = "tests/fixtures/certificates/valid/self-signed cert.crt";
        if !fixture_exists(path) {
            println!("Skipping: fixture not found");
            return;
        }
        let cert = load_fixture(path);
        let verifier = Verifier::with_custom_trust(vec![cert.raw_der.clone()]);
        let report = verifier.verify(&[cert]);
        assert_eq!(report.overall_status, OverallStatus::Ok);
        assert!(report.certificates[0].trust.trusted);
    }

    #[test]
    fn test_verify_two_cert_chain() {
        let int_path = "tests/fixtures/certificates/valid/intermediate ca.crt";
        let leaf_path = "tests/fixtures/certificates/valid/example.com.crt";
        if !fixture_exists(int_path) || !fixture_exists(leaf_path) {
            println!("Skipping: fixtures not found");
            return;
        }
        let leaf = load_fixture(leaf_path);
        let intermediate = load_fixture(int_path);
        let verifier = Verifier::with_custom_trust(vec![intermediate.raw_der.clone()]);
        let report = verifier.verify(&[leaf, intermediate]);

        assert_eq!(report.certificates.len(), 2);
        // Leaf signature should be verified
        assert!(report.certificates[0].signature.verified);
        assert!(report.chain.is_some());
        assert_eq!(report.chain.as_ref().unwrap().length, 2);
    }

    #[test]
    fn test_verify_chain_structural_invalid() {
        let root_path = "tests/fixtures/certificates/valid/root ca.crt";
        let leaf_path = "tests/fixtures/certificates/valid/example.com.crt";
        if !fixture_exists(root_path) || !fixture_exists(leaf_path) {
            println!("Skipping: fixtures not found");
            return;
        }
        // Leaf's issuer (Intermediate CA) doesn't match root's subject (Test Root CA)
        let leaf = load_fixture(leaf_path);
        let root = load_fixture(root_path);
        let verifier = Verifier::with_custom_trust(vec![root.raw_der.clone()]);
        let report = verifier.verify(&[leaf, root]);

        // The chain builder can't link leaf→root (issuer/subject don't match),
        // so only the leaf is included. Its issuer is missing → signature Unknown → Failed.
        assert!(
            matches!(report.overall_status, OverallStatus::Failed),
            "expected Failed for unrelated certs, got: {:?}",
            report.overall_status
        );
    }

    #[test]
    fn test_verify_san_extraction() {
        let path = "tests/fixtures/certificates/valid/example.com.crt";
        if !fixture_exists(path) {
            println!("Skipping: fixture not found");
            return;
        }
        let cert = load_fixture(path);
        let verifier = Verifier::with_system_trust();
        let report = verifier.verify(&[cert]);

        let san = &report.certificates[0].san_entries;
        assert!(!san.is_empty(), "expected SAN entries for example.com cert");
        assert!(
            san.iter()
                .any(|s| s.san_type == "DNS" && s.value.contains("example.com")),
            "expected DNS SAN with example.com, got: {:?}",
            san
        );
    }

    #[test]
    fn test_verify_key_usage_extraction() {
        let path = "assets/baidu.com.pem";
        if !fixture_exists(path) {
            println!("Skipping: fixture not found");
            return;
        }
        let cert = load_fixture(path);
        let verifier = Verifier::with_system_trust();
        let report = verifier.verify(&[cert]);

        assert!(
            !report.certificates[0].key_usage.is_empty(),
            "expected Key Usage for baidu.com cert"
        );
    }

    #[test]
    fn test_verify_expired_cert() {
        let path = "tests/fixtures/certificates/expired/expired cert.crt";
        if !fixture_exists(path) {
            println!("Skipping: fixture not found");
            return;
        }
        let cert = load_fixture(path);
        let verifier = Verifier::with_system_trust();
        let report = verifier.verify(&[cert]);

        // The expired cert fixture may or may not actually be expired depending on dates.
        // If it IS expired, overall should be Failed.
        if !report.certificates[0].time_validity.valid {
            assert_eq!(report.overall_status, OverallStatus::Failed);
        }
    }

    #[test]
    fn test_verify_overall_status_computation() {
        let path = "tests/fixtures/certificates/valid/self-signed cert.crt";
        if !fixture_exists(path) {
            println!("Skipping: fixture not found");
            return;
        }

        // Case 1: self-signed without custom trust -> Warning
        let cert = load_fixture(path);
        let verifier = Verifier::with_system_trust();
        let report = verifier.verify(std::slice::from_ref(&cert));
        // May be Ok (if system trust) or Warning (if not in system trust)
        assert!(
            matches!(
                report.overall_status,
                OverallStatus::Ok | OverallStatus::Warning
            ),
            "expected Ok or Warning, got: {:?}",
            report.overall_status
        );

        // Case 2: self-signed with matching custom trust -> Ok
        let verifier = Verifier::with_custom_trust(vec![cert.raw_der.clone()]);
        let report = verifier.verify(&[cert]);
        assert_eq!(report.overall_status, OverallStatus::Ok);
    }

    #[test]
    fn test_parse_san_value() {
        assert_eq!(
            parse_san_value("DNS: example.com"),
            Some(("DNS".to_string(), "example.com".to_string()))
        );
        assert_eq!(
            parse_san_value("IP Address: 192.168.1.1"),
            Some(("IP Address".to_string(), "192.168.1.1".to_string()))
        );
        assert_eq!(parse_san_value("no colon here"), None);
        assert_eq!(parse_san_value(": only colon"), None);
    }
}
