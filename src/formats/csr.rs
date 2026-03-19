//! Certificate Signing Request (CSR) parser for PKCS#10.
//!
//! This module handles CSR (also known as PKCS#10) formatted files,
//! typically .csr or .p10 files, used to request certificate signing.
//! Uses `x509_parser::certification_request::X509CertificationRequest` for proper ASN.1 parsing.

use crate::cert::{CertError, CertField, Result};
use serde::Serialize;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::cri_attributes::ParsedCriAttribute;
use x509_parser::prelude::*;

use crate::utils::{describe_oid, format_hex_block};

// ── Public data model ──────────────────────────────────────────────

/// Unique identifier for a CSR.
///
/// Based on SHA-256 fingerprint of the DER-encoded CSR data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CsrId(pub String);

impl CsrId {
    /// Create a CsrId from raw DER data.
    pub fn from_der(der: &[u8]) -> Self {
        Self(crate::cert::format_digest_hex(&Sha256::digest(der)))
    }
}

impl std::fmt::Display for CsrId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// High-level parsed CSR holding the field tree.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedCsr {
    /// Unique identifier for this CSR (SHA-256 based).
    pub id: CsrId,
    /// Display name for this CSR (typically the CN from subject).
    pub display_name: String,
    /// Full subject DN.
    pub subject: String,
    /// SHA-256 fingerprint in colon-separated hex format.
    pub sha256_fingerprint: String,
    /// SHA-1 fingerprint in colon-separated hex format.
    pub sha1_fingerprint: String,
    /// Signature algorithm.
    pub signature_algorithm: String,
    /// Root-level fields forming the CSR tree.
    pub fields: Vec<CertField>,
    /// Raw DER-encoded CSR bytes (for export).
    pub raw_der: Vec<u8>,
}

impl ParsedCsr {
    /// Export this CSR as a PEM-encoded string.
    pub fn to_pem(&self) -> String {
        use base64::prelude::*;

        let b64 = BASE64_STANDARD.encode(&self.raw_der);
        let mut pem = String::with_capacity(b64.len() + 64);
        pem.push_str("-----BEGIN CERTIFICATE REQUEST-----\n");

        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            pem.push('\n');
        }

        pem.push_str("-----END CERTIFICATE REQUEST-----\n");
        pem
    }
}

// ── Parsing entry points ────────────────────────────────────────────

/// Parse a single PEM-encoded CSR and return a [`ParsedCsr`].
#[allow(dead_code)]
pub fn parse_csr_pem(pem_data: &[u8]) -> Result<ParsedCsr> {
    let (_, pem_obj) = x509_parser::pem::parse_x509_pem(pem_data)
        .map_err(|e| CertError::pem(format!("PEM parse error: {e}")))?;

    if !pem_obj.label.eq_ignore_ascii_case("CERTIFICATE REQUEST") {
        return Err(CertError::pem(format!(
            "Expected CERTIFICATE REQUEST PEM block, got '{}'",
            pem_obj.label
        )));
    }

    let der_data = pem_obj.contents.to_vec();
    let (_, csr) = X509CertificationRequest::from_der(&pem_obj.contents)
        .map_err(|e| CertError::pem(format!("CSR parse error: {e}")))?;

    Ok(build_csr_tree(&csr, der_data))
}

/// Parse all PEM CSR blocks from data, returning a list of parsed CSRs.
#[allow(dead_code)]
pub fn parse_csr_pem_all(pem_data: &[u8]) -> Vec<Result<ParsedCsr>> {
    let mut results = Vec::new();
    let mut remaining = pem_data;

    while let Ok((rest, pem_obj)) = x509_parser::pem::parse_x509_pem(remaining) {
        if pem_obj.label.eq_ignore_ascii_case("CERTIFICATE REQUEST") {
            match X509CertificationRequest::from_der(&pem_obj.contents) {
                Ok((_, csr)) => {
                    results.push(Ok(build_csr_tree(&csr, pem_obj.contents.to_vec())));
                }
                Err(e) => {
                    results.push(Err(CertError::pem(format!("CSR parse error: {e}"))));
                }
            }
        }
        remaining = rest;
        if remaining.is_empty() {
            break;
        }
    }

    if results.is_empty() {
        results.push(Err(CertError::pem("No valid PEM CSR blocks found")));
    }

    results
}

/// Parse DER-encoded CSR data and return a [`ParsedCsr`].
pub fn parse_csr_der(der_data: &[u8]) -> Result<ParsedCsr> {
    let (_, csr) =
        X509CertificationRequest::from_der(der_data).map_err(|e| CertError::der(format!("{e}")))?;
    Ok(build_csr_tree(&csr, der_data.to_vec()))
}

/// Detect format and parse. For PEM, extracts all CSR blocks.
#[allow(dead_code)]
pub fn parse_csrs(data: &[u8]) -> Vec<Result<ParsedCsr>> {
    if is_pem_csr(data) {
        parse_csr_pem_all(data)
    } else {
        match parse_csr_der(data) {
            Ok(csr) => vec![Ok(csr)],
            Err(e) => vec![Err(e)],
        }
    }
}

/// Detect if data is a PEM-encoded CSR.
#[allow(dead_code)]
pub fn is_pem_csr(data: &[u8]) -> bool {
    use crate::utils::bytes_contains_any;
    bytes_contains_any(
        data,
        &[
            "-----BEGIN CERTIFICATE REQUEST-----",
            "-----BEGIN NEW CERTIFICATE REQUEST-----",
            "-----BEGIN CERTIFICATE-REQUEST-----",
        ],
    )
}

// ── Tree construction ──────────────────────────────────────────────

fn build_csr_tree(csr: &X509CertificationRequest<'_>, der_data: Vec<u8>) -> ParsedCsr {
    let info = &csr.certification_request_info;
    let id = CsrId::from_der(&der_data);
    let display_name = extract_cn(&info.subject).unwrap_or_else(|| "Unknown".into());

    let sha256_fingerprint = crate::cert::format_digest_hex(&Sha256::digest(&der_data));
    let sha1_fingerprint = crate::cert::format_digest_hex(&Sha1::digest(&der_data));

    let subject = info.subject.to_string();
    let signature_algorithm = describe_oid(&csr.signature_algorithm.algorithm);

    let mut fields = Vec::new();

    // Version
    fields.push(CertField::leaf(
        "Version",
        format!("V{}", info.version.0 + 1),
    ));

    // Subject
    fields.push(crate::cert::build_name_field("Subject", &info.subject));

    // Subject Public Key Info
    fields.push(crate::cert::build_spki_field(&info.subject_pki));

    // Attributes (extensions, challenge password, etc.)
    let attr_fields = build_attributes(info);
    if !attr_fields.is_empty() {
        fields.push(CertField::container("Attributes", attr_fields));
    }

    // Signature Algorithm
    fields.push(CertField::leaf("Signature Algorithm", &signature_algorithm));

    // Signature Value
    let sig_hex = hex::encode(&*csr.signature_value.data);
    fields.push(CertField::leaf(
        "Signature Value",
        format_hex_block(&sig_hex),
    ));

    // Fingerprints
    fields.push(CertField::container(
        "Fingerprints",
        vec![
            CertField::leaf("SHA-256", &sha256_fingerprint),
            CertField::leaf("SHA-1", &sha1_fingerprint),
        ],
    ));

    ParsedCsr {
        id,
        display_name,
        subject,
        sha256_fingerprint,
        sha1_fingerprint,
        signature_algorithm,
        fields,
        raw_der: der_data,
    }
}

fn build_attributes(
    info: &x509_parser::certification_request::X509CertificationRequestInfo<'_>,
) -> Vec<CertField> {
    let mut attr_fields = Vec::new();

    for attr in info.iter_attributes() {
        match attr.parsed_attribute() {
            ParsedCriAttribute::ExtensionRequest(ext_req) => {
                let ext_children: Vec<CertField> = ext_req
                    .extensions
                    .iter()
                    .map(crate::cert::extensions::build_extension_field)
                    .collect();
                if !ext_children.is_empty() {
                    attr_fields.push(CertField::container("Extension Request", ext_children));
                }
            }
            ParsedCriAttribute::ChallengePassword(password) => {
                attr_fields.push(CertField::leaf("Challenge Password", &password.0));
            }
            ParsedCriAttribute::UnsupportedAttribute => {
                attr_fields.push(CertField::leaf(
                    describe_oid(&attr.oid),
                    format_hex_block(&hex::encode(attr.value)),
                ));
            }
        }
    }

    attr_fields
}

fn extract_cn(name: &X509Name<'_>) -> Option<String> {
    crate::cert::extract_cn(name)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    const TEST_CSR: &[u8] = include_bytes!("../../assets/test.csr");
    const TEST_CSR_EXTS: &[u8] = include_bytes!("../../assets/test_with_exts.csr");

    #[test]
    fn test_is_pem_csr_with_cert() {
        let cert = include_bytes!("../../assets/baidu.com.pem");
        assert!(!is_pem_csr(cert));
    }

    #[test]
    fn test_is_pem_csr_with_csr() {
        assert!(is_pem_csr(TEST_CSR));
    }

    #[test]
    fn test_parse_csr_pem() {
        let result = parse_csr_pem(TEST_CSR);
        assert!(result.is_ok(), "Failed to parse CSR: {result:?}");
    }

    #[test]
    fn test_parse_csr_der() {
        // Extract DER from PEM first
        let pem_str = std::str::from_utf8(TEST_CSR).unwrap();
        let mut b64 = String::new();
        let mut in_data = false;
        for line in pem_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("-----BEGIN") {
                in_data = true;
                continue;
            }
            if trimmed.starts_with("-----END") {
                break;
            }
            if in_data {
                b64.push_str(trimmed);
            }
        }
        let der = base64::prelude::BASE64_STANDARD
            .decode(&b64)
            .expect("valid base64");

        let result = parse_csr_der(&der);
        assert!(result.is_ok(), "Failed to parse DER CSR: {result:?}");
    }

    #[test]
    fn test_parsed_csr_has_display_name() {
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        assert_eq!(csr.display_name, "Test Certificate");
    }

    #[test]
    fn test_parsed_csr_has_subject() {
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        assert!(
            csr.subject.contains("Test Certificate"),
            "Subject should contain CN: {}",
            csr.subject
        );
    }

    #[test]
    fn test_parsed_csr_has_expected_fields() {
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        let labels: Vec<&str> = csr.fields.iter().map(|f| f.label.as_str()).collect();
        assert!(labels.contains(&"Version"), "Missing Version field");
        assert!(labels.contains(&"Subject"), "Missing Subject field");
        assert!(
            labels.contains(&"Subject Public Key Info"),
            "Missing SPKI field"
        );
        assert!(
            labels.contains(&"Signature Algorithm"),
            "Missing Signature Algorithm"
        );
        assert!(
            labels.contains(&"Signature Value"),
            "Missing Signature Value"
        );
        assert!(labels.contains(&"Fingerprints"), "Missing Fingerprints");
    }

    #[test]
    fn test_parsed_csr_version() {
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        let version = csr.fields.iter().find(|f| f.label == "Version").unwrap();
        assert_eq!(version.value.as_deref(), Some("V1"));
    }

    #[test]
    fn test_parsed_csr_signature_algorithm() {
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        assert!(csr.signature_algorithm.contains("RSA"));
    }

    #[test]
    fn test_parsed_csr_fingerprints() {
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        assert!(
            !csr.sha256_fingerprint.is_empty(),
            "SHA-256 fingerprint should not be empty"
        );
        assert!(
            !csr.sha1_fingerprint.is_empty(),
            "SHA-1 fingerprint should not be empty"
        );
        // Fingerprint format: XX:XX:XX:...
        assert!(csr.sha256_fingerprint.contains(':'));
    }

    #[test]
    fn test_parse_invalid_csr() {
        let result = parse_csr_pem(b"not a csr");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_csr_with_extensions() {
        let csr = parse_csr_pem(TEST_CSR_EXTS).unwrap();
        let labels: Vec<&str> = csr.fields.iter().map(|f| f.label.as_str()).collect();
        assert!(
            labels.contains(&"Attributes"),
            "CSR with extensions should have Attributes field"
        );

        // Check the extensions inside attributes
        let attrs = csr.fields.iter().find(|f| f.label == "Attributes").unwrap();
        assert!(attrs.has_children());
    }

    #[test]
    fn test_parse_csr_san_extension() {
        let csr = parse_csr_pem(TEST_CSR_EXTS).unwrap();
        let attrs = csr.fields.iter().find(|f| f.label == "Attributes").unwrap();
        let ext_req = attrs
            .children
            .iter()
            .find(|c| c.label == "Extension Request");
        assert!(
            ext_req.is_some(),
            "Should have Extension Request in attributes"
        );

        let ext_req = ext_req.unwrap();
        let has_san = ext_req.children.iter().any(|ext| {
            ext.label.contains("Subject Alternative Name") || ext.label.contains("subjectAltName")
        });
        assert!(has_san, "Extension Request should include SAN");
    }

    #[test]
    fn test_csr_to_pem() {
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        let pem = csr.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(pem.ends_with("-----END CERTIFICATE REQUEST-----\n"));

        // Round-trip: parse the PEM we just generated
        let roundtrip = parse_csr_pem(pem.as_bytes()).unwrap();
        assert_eq!(roundtrip.subject, csr.subject);
    }

    #[test]
    fn test_csr_id_from_der() {
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        let id2 = CsrId::from_der(&csr.raw_der);
        assert_eq!(csr.id, id2);
    }

    #[test]
    fn test_csr_id_is_sha256() {
        use sha2::Sha256;
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        let expected = crate::cert::format_digest_hex(&Sha256::digest(&csr.raw_der));
        assert_eq!(csr.id.0, expected);
    }

    #[test]
    fn test_fingerprint_matches_openssl() {
        // Verify SHA-256 fingerprint matches openssl output format
        let csr = parse_csr_pem(TEST_CSR).unwrap();
        // The fingerprint should be 95 hex chars (32 bytes * 3 - 1 colons)
        let parts: Vec<&str> = csr.sha256_fingerprint.split(':').collect();
        assert_eq!(parts.len(), 32, "SHA-256 fingerprint should have 32 octets");
    }
}
