//! Certificate parsing and structured field extraction.
//!
//! This module converts raw PEM/DER certificate bytes into a tree of [`CertField`]
//! nodes that the UI can render as a collapsible hierarchy.

mod error;
mod extensions;
pub mod format;

pub use error::{CertError, Result};

use sha1::{Digest, Sha1};
use sha2::Sha256;
use x509_parser::prelude::*;

use crate::utils::{describe_oid, format_bytes_hex_colon as format_bytes_hex, format_hex_block};

// ── Public data model ──────────────────────────────────────────────

/// A single node in the certificate field tree.
#[derive(Debug, Clone)]
pub struct CertField {
    /// Human-readable label for this field (e.g. "Subject", "Serial Number").
    pub label: String,
    /// Optional string value. `None` for pure container nodes.
    pub value: Option<String>,
    /// Child fields that can be expanded in the UI.
    pub children: Vec<CertField>,
}

impl CertField {
    /// Create a leaf field with a label and value.
    #[must_use]
    pub fn leaf(label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            value: Some(value.into()),
            children: Vec::new(),
        }
    }

    /// Create a container field that holds children.
    #[must_use]
    pub fn container(label: impl Into<String>, children: Vec<CertField>) -> Self {
        Self {
            label: label.into(),
            value: None,
            children,
        }
    }

    /// Create a container field with both a summary value and children.
    #[must_use]
    pub fn node(
        label: impl Into<String>,
        value: impl Into<String>,
        children: Vec<CertField>,
    ) -> Self {
        Self {
            label: label.into(),
            value: Some(value.into()),
            children,
        }
    }

    /// Returns `true` if this field has child fields.
    pub fn has_children(&self) -> bool {
        !self.children.is_empty()
    }
}

// ── Validity status ─────────────────────────────────────────────────

/// Certificate validity status relative to the current time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidityStatus {
    /// Certificate is currently valid (notBefore ≤ now ≤ notAfter).
    Valid,
    /// Certificate is not yet valid (now < notBefore).
    NotYetValid,
    /// Certificate has expired (now > notAfter).
    Expired,
}

impl ValidityStatus {
    /// Check validity status against current time.
    pub fn check(not_before: &ASN1Time, not_after: &ASN1Time) -> Self {
        let now = chrono::Utc::now().timestamp();
        let not_before_ts = not_before.timestamp();
        let not_after_ts = not_after.timestamp();

        if now < not_before_ts {
            Self::NotYetValid
        } else if now > not_after_ts {
            Self::Expired
        } else {
            Self::Valid
        }
    }
}

// ── Parsed certificate wrapper ─────────────────────────────────────

/// Unique identifier for a certificate.
///
/// Based on SHA-256 fingerprint of the DER-encoded certificate data.
/// This provides a stable identifier that can be used for duplicate detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertId(String);

impl CertId {
    /// Create a CertId from raw DER data.
    pub fn from_der(der: &[u8]) -> Self {
        Self(format_digest_hex(&Sha256::digest(der)))
    }
}

impl std::fmt::Display for CertId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// High-level parsed certificate holding the field tree.
///
/// This structure contains all parsed certificate data in a format suitable
/// for UI display. The `fields` vector contains the hierarchical representation
/// of certificate elements.
#[derive(Debug, Clone)]
#[expect(dead_code)] // Fields are kept for future features (export, search, etc.)
pub struct ParsedCert {
    /// Unique identifier for this certificate (SHA-256 based).
    pub id: CertId,
    /// Display name for this certificate (typically the CN or filename).
    pub display_name: String,
    /// Serial number in colon-separated hex format.
    pub serial_number: String,
    /// SHA-256 fingerprint in colon-separated hex format.
    pub sha256_fingerprint: String,
    /// SHA-1 fingerprint in colon-separated hex format.
    pub sha1_fingerprint: String,
    /// Current validity status of the certificate.
    pub validity_status: ValidityStatus,
    /// Not Before timestamp as a formatted string.
    pub not_before: String,
    /// Not After timestamp as a formatted string.
    pub not_after: String,
    /// Issuer DN as a string.
    pub issuer: String,
    /// Subject DN as a string.
    pub subject: String,
    /// Root-level fields forming the certificate tree.
    pub fields: Vec<CertField>,
    /// Raw DER-encoded certificate bytes (for export).
    pub raw_der: Vec<u8>,
}

impl ParsedCert {
    /// Export this certificate as a PEM-encoded string.
    pub fn to_pem(&self) -> String {
        use base64::prelude::*;

        let b64 = BASE64_STANDARD.encode(&self.raw_der);
        let mut pem = String::with_capacity(b64.len() + 64);
        pem.push_str("-----BEGIN CERTIFICATE-----\n");

        // Split base64 into 64-character lines
        for chunk in b64.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
            pem.push('\n');
        }

        pem.push_str("-----END CERTIFICATE-----\n");
        pem
    }
}

// ── Parsing entry point ────────────────────────────────────────────

/// Parse PEM-encoded certificate data and return a [`ParsedCert`].
///
/// Supports single-certificate PEM blocks (`-----BEGIN CERTIFICATE-----`).
pub fn parse_pem_certificate(pem_data: &[u8]) -> Result<ParsedCert> {
    let (_, pem) = parse_x509_pem(pem_data).map_err(|e| CertError::pem(format!("{e}")))?;
    let der_data = pem.contents.to_vec();
    let (_, cert) = parse_x509_certificate(&pem.contents)
        .map_err(|e| CertError::pem(format!("X.509 parse error: {e}")))?;
    Ok(build_cert_tree(&cert, der_data))
}

/// Parse all PEM certificate blocks from data, returning a list of parsed certificates.
///
/// Supports PEM files containing multiple certificate blocks (certificate chains).
pub fn parse_pem_certificates(pem_data: &[u8]) -> Vec<Result<ParsedCert>> {
    let mut results = Vec::new();
    let mut remaining = pem_data;

    while let Ok((rest, pem)) = parse_x509_pem(remaining) {
        match parse_x509_certificate(&pem.contents) {
            Ok((_, cert)) => {
                results.push(Ok(build_cert_tree(&cert, pem.contents.to_vec())));
            }
            Err(e) => {
                results.push(Err(CertError::pem(format!("X.509 parse error: {e}"))));
            }
        }
        remaining = rest;
        if remaining.is_empty() {
            break;
        }
    }

    if results.is_empty() {
        results.push(Err(CertError::pem("No valid PEM certificate blocks found")));
    }

    results
}

/// Parse DER-encoded certificate data and return a [`ParsedCert`].
pub fn parse_der_certificate(der_data: &[u8]) -> Result<ParsedCert> {
    let (_, cert) = parse_x509_certificate(der_data).map_err(|e| CertError::der(format!("{e}")))?;
    Ok(build_cert_tree(&cert, der_data.to_vec()))
}

/// Detect format and parse. For PEM, extracts all certificate blocks.
pub fn parse_certificates(data: &[u8]) -> Vec<Result<ParsedCert>> {
    if data.starts_with(b"-----BEGIN") {
        parse_pem_certificates(data)
    } else {
        match parse_der_certificate(data) {
            Ok(cert) => vec![Ok(cert)],
            Err(e) => vec![Err(e)],
        }
    }
}

/// Detect format and parse a single certificate (for backward compatibility).
pub fn parse_certificate(data: &[u8]) -> Result<ParsedCert> {
    if data.starts_with(b"-----BEGIN") {
        parse_pem_certificate(data)
    } else {
        parse_der_certificate(data)
    }
}

// ── Tree construction ──────────────────────────────────────────────

fn build_cert_tree(cert: &X509Certificate<'_>, der_data: Vec<u8>) -> ParsedCert {
    let tbs = &cert.tbs_certificate;
    let id = CertId::from_der(&der_data);
    let display_name = extract_cn(&tbs.subject).unwrap_or_else(|| "Unknown".into());
    let serial_number = format_bytes_hex(tbs.raw_serial());

    // Calculate fingerprints
    let sha256_fingerprint = format_digest_hex(&Sha256::digest(&der_data));
    let sha1_fingerprint = format_digest_hex(&Sha1::digest(&der_data));

    // Validity
    let not_before = format_asn1_time(&tbs.validity.not_before);
    let not_after = format_asn1_time(&tbs.validity.not_after);
    let validity_status = ValidityStatus::check(&tbs.validity.not_before, &tbs.validity.not_after);

    // Issuer and Subject strings
    let issuer = tbs.issuer.to_string();
    let subject = tbs.subject.to_string();

    let mut fields = Vec::new();

    // Version
    fields.push(CertField::leaf(
        "Version",
        format!("V{}", tbs.version.0 + 1),
    ));

    // Serial Number
    fields.push(CertField::leaf("Serial Number", &serial_number));

    // Signature Algorithm
    fields.push(CertField::leaf(
        "Signature Algorithm",
        describe_oid(&cert.signature_algorithm.algorithm),
    ));

    // Issuer
    fields.push(build_name_field("Issuer", &tbs.issuer));

    // Validity
    fields.push(build_validity_field(&tbs.validity));

    // Subject
    fields.push(build_name_field("Subject", &tbs.subject));

    // Subject Public Key Info
    fields.push(build_spki_field(&tbs.subject_pki));

    // Extensions
    let extensions = tbs.extensions();
    if !extensions.is_empty() {
        let ext_fields: Vec<CertField> = extensions
            .iter()
            .map(extensions::build_extension_field)
            .collect();
        fields.push(CertField::container("Extensions", ext_fields));
    }

    // Signature Value
    let sig_hex = hex::encode(&*cert.signature_value.data);
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

    ParsedCert {
        id,
        display_name,
        serial_number,
        sha256_fingerprint,
        sha1_fingerprint,
        validity_status,
        not_before,
        not_after,
        issuer,
        subject,
        fields,
        raw_der: der_data,
    }
}

// ── Helper formatters ──────────────────────────────────────────────

/// Format a hash digest (implements `AsRef<[u8]>`) as a colon-separated uppercase hex string.
pub(crate) fn format_digest_hex<D: AsRef<[u8]>>(digest: &D) -> String {
    crate::utils::format_bytes_hex_colon(digest.as_ref())
}

fn extract_cn(name: &X509Name<'_>) -> Option<String> {
    for rdn in name.iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                return attr.as_str().ok().map(String::from);
            }
        }
    }
    None
}

fn build_name_field(label: &str, name: &X509Name<'_>) -> CertField {
    let mut children = Vec::new();
    for rdn in name.iter() {
        for attr in rdn.iter() {
            let oid_desc = describe_oid(attr.attr_type());
            let val = attr.as_str().unwrap_or("(binary)").to_string();
            children.push(CertField::leaf(&oid_desc, &val));
        }
    }
    let summary = name.to_string();
    CertField::node(label, summary, children)
}

fn build_validity_field(validity: &Validity) -> CertField {
    let not_before = format_asn1_time(&validity.not_before);
    let not_after = format_asn1_time(&validity.not_after);
    CertField::container(
        "Validity",
        vec![
            CertField::leaf("Not Before", &not_before),
            CertField::leaf("Not After", &not_after),
        ],
    )
}

fn format_asn1_time(t: &ASN1Time) -> String {
    let ts = t.timestamp();
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| format!("timestamp {ts}"))
}

fn build_spki_field(spki: &SubjectPublicKeyInfo<'_>) -> CertField {
    let algo = describe_oid(&spki.algorithm.algorithm);
    let key_hex = hex::encode(&*spki.subject_public_key.data);
    let key_bits = spki.subject_public_key.data.len() * 8;
    CertField::container(
        "Subject Public Key Info",
        vec![
            CertField::leaf("Algorithm", &algo),
            CertField::leaf("Key Size", format!("{key_bits} bits")),
            CertField::leaf("Public Key", format_hex_block(&key_hex)),
        ],
    )
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const BAIDU_PEM: &[u8] = include_bytes!("../assets/baidu.com.pem");

    #[test]
    fn test_parse_pem_certificate_success() {
        let result = parse_pem_certificate(BAIDU_PEM);
        assert!(result.is_ok(), "Failed to parse baidu.com PEM: {result:?}");
    }

    #[test]
    fn test_parsed_cert_has_display_name() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        assert!(
            !cert.display_name.is_empty(),
            "Display name should not be empty"
        );
    }

    #[test]
    fn test_parsed_cert_has_expected_fields() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let labels: Vec<&str> = cert.fields.iter().map(|f| f.label.as_str()).collect();
        assert!(labels.contains(&"Version"), "Missing Version field");
        assert!(labels.contains(&"Serial Number"), "Missing Serial Number");
        assert!(
            labels.contains(&"Signature Algorithm"),
            "Missing Signature Algorithm"
        );
        assert!(labels.contains(&"Issuer"), "Missing Issuer");
        assert!(labels.contains(&"Validity"), "Missing Validity");
        assert!(labels.contains(&"Subject"), "Missing Subject");
        assert!(labels.contains(&"Subject Public Key Info"), "Missing SPKI");
        assert!(labels.contains(&"Extensions"), "Missing Extensions");
        assert!(
            labels.contains(&"Signature Value"),
            "Missing Signature Value"
        );
    }

    #[test]
    fn test_version_is_v3() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let version = cert.fields.iter().find(|f| f.label == "Version").unwrap();
        assert_eq!(version.value.as_deref(), Some("V3"));
    }

    #[test]
    fn test_issuer_has_children() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let issuer = cert.fields.iter().find(|f| f.label == "Issuer").unwrap();
        assert!(issuer.has_children(), "Issuer should have child RDN fields");
    }

    #[test]
    fn test_subject_contains_baidu() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let subject = cert.fields.iter().find(|f| f.label == "Subject").unwrap();
        let summary = subject.value.as_deref().unwrap_or("");
        assert!(
            summary.contains("baidu") || summary.contains("Baidu"),
            "Subject should mention baidu: {summary}"
        );
    }

    #[test]
    fn test_validity_has_not_before_and_not_after() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let validity = cert.fields.iter().find(|f| f.label == "Validity").unwrap();
        let child_labels: Vec<&str> = validity.children.iter().map(|f| f.label.as_str()).collect();
        assert!(child_labels.contains(&"Not Before"));
        assert!(child_labels.contains(&"Not After"));
    }

    #[test]
    fn test_spki_has_algorithm_and_key() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let spki = cert
            .fields
            .iter()
            .find(|f| f.label == "Subject Public Key Info")
            .unwrap();
        let child_labels: Vec<&str> = spki.children.iter().map(|f| f.label.as_str()).collect();
        assert!(child_labels.contains(&"Algorithm"));
        assert!(child_labels.contains(&"Key Size"));
        assert!(child_labels.contains(&"Public Key"));
    }

    #[test]
    fn test_extensions_contain_san() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let extensions = cert
            .fields
            .iter()
            .find(|f| f.label == "Extensions")
            .unwrap();
        let has_san = extensions.children.iter().any(|ext| {
            ext.label.contains("Subject Alternative Name") || ext.label.contains("subjectAltName")
        });
        assert!(has_san, "Extensions should include SAN");
    }

    #[test]
    fn test_san_contains_baidu_domains() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let extensions = cert
            .fields
            .iter()
            .find(|f| f.label == "Extensions")
            .unwrap();
        let san = extensions
            .children
            .iter()
            .find(|ext| {
                ext.label.contains("Subject Alternative Name")
                    || ext.label.contains("subjectAltName")
            })
            .expect("SAN extension not found");
        let alt_names = san
            .children
            .iter()
            .find(|c| c.label == "Alternative Names")
            .expect("Alternative Names container not found");
        let all_names: Vec<&str> = alt_names
            .children
            .iter()
            .filter_map(|c| c.value.as_deref())
            .collect();
        assert!(
            all_names.iter().any(|n| n.contains("baidu")),
            "SAN should contain baidu domains: {all_names:?}"
        );
    }

    #[test]
    fn test_parse_invalid_pem_returns_error() {
        let result = parse_pem_certificate(b"not a certificate");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_der_returns_error() {
        let result = parse_der_certificate(b"\x30\x00");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_certificate_auto_detects_pem() {
        let result = parse_certificate(BAIDU_PEM);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cert_field_leaf() {
        let f = CertField::leaf("Label", "Value");
        assert_eq!(f.label, "Label");
        assert_eq!(f.value.as_deref(), Some("Value"));
        assert!(!f.has_children());
    }

    #[test]
    fn test_cert_field_container() {
        let f = CertField::container("Parent", vec![CertField::leaf("Child", "val")]);
        assert!(f.has_children());
        assert!(f.value.is_none());
    }

    #[test]
    fn test_cert_field_node() {
        let f = CertField::node("Label", "Summary", vec![CertField::leaf("C", "v")]);
        assert!(f.has_children());
        assert_eq!(f.value.as_deref(), Some("Summary"));
    }

    #[test]
    fn test_format_bytes_hex_formatting() {
        let bytes = &[0x0E, 0x7F, 0xA9, 0x2B];
        let result = format_bytes_hex(bytes);
        assert_eq!(result, "0E:7F:A9:2B");
    }

    #[test]
    fn test_format_hex_block_formatting() {
        let result = format_hex_block("aabb");
        assert_eq!(result, "aa:bb");
    }

    #[test]
    fn test_parsed_cert_has_raw_der() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        assert!(!cert.raw_der.is_empty(), "raw_der should not be empty");
    }

    #[test]
    fn test_to_pem_output() {
        let cert = parse_pem_certificate(BAIDU_PEM).unwrap();
        let pem = cert.to_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
    }

    #[test]
    fn test_base64_encode() {
        use base64::prelude::*;
        assert_eq!(BASE64_STANDARD.encode(b"\x00"), "AA==");
        assert_eq!(BASE64_STANDARD.encode(b"\x00\x00"), "AAA=");
        assert_eq!(BASE64_STANDARD.encode(b"\x00\x00\x00"), "AAAA");
        assert_eq!(BASE64_STANDARD.encode(b"Hello"), "SGVsbG8=");
    }
}
