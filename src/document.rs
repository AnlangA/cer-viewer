//! Unified document model for certificates and CSRs.
//!
//! Provides a [`Document`] enum that wraps both [`ParsedCert`] and [`ParsedCsr`],
//! allowing them to coexist in the same tab list and be loaded from the same files.

use crate::cert::{CertField, ParsedCert};
use crate::formats::csr::{self, ParsedCsr};
use crate::utils::bytes_contains_any;
use serde::Serialize;

/// A document that can be displayed in the viewer — either a certificate or a CSR.
#[derive(Debug, Clone, Serialize)]
pub enum Document {
    Certificate(ParsedCert),
    Csr(ParsedCsr),
}

impl Document {
    /// Human-readable name for this document (CN or "Unknown").
    pub fn display_name(&self) -> &str {
        match self {
            Document::Certificate(cert) => &cert.display_name,
            Document::Csr(csr) => &csr.display_name,
        }
    }

    /// The root-level fields forming the tree.
    #[allow(dead_code)]
    pub fn fields(&self) -> &Vec<CertField> {
        match self {
            Document::Certificate(cert) => &cert.fields,
            Document::Csr(csr) => &csr.fields,
        }
    }

    /// Unique identifier string for deduplication.
    pub fn id_str(&self) -> &str {
        match self {
            Document::Certificate(cert) => &cert.id.0,
            Document::Csr(csr) => &csr.id.0,
        }
    }

    /// Whether this document is a CSR.
    pub fn is_csr(&self) -> bool {
        matches!(self, Document::Csr(_))
    }

    /// Raw DER bytes.
    #[allow(dead_code)]
    pub fn raw_der(&self) -> &[u8] {
        match self {
            Document::Certificate(cert) => &cert.raw_der,
            Document::Csr(csr) => &csr.raw_der,
        }
    }

    /// Export as PEM string.
    #[allow(dead_code)]
    pub fn to_pem(&self) -> String {
        match self {
            Document::Certificate(cert) => cert.to_pem(),
            Document::Csr(csr) => csr.to_pem(),
        }
    }

    /// Subject string.
    #[allow(dead_code)]
    pub fn subject(&self) -> &str {
        match self {
            Document::Certificate(cert) => &cert.subject,
            Document::Csr(csr) => &csr.subject,
        }
    }
}

/// Load all documents (certificates and/or CSRs) from raw file data.
///
/// Supports PEM files with mixed certificate and CSR blocks, as well as DER data.
/// For DER, tries certificate parse first, then CSR.
pub fn load_documents(data: &[u8]) -> Vec<std::result::Result<Document, String>> {
    if data.starts_with(b"-----BEGIN") {
        load_pem_documents(data)
    } else {
        load_der_document(data)
    }
}

fn load_pem_documents(data: &[u8]) -> Vec<std::result::Result<Document, String>> {
    let mut results = Vec::new();
    let mut remaining = data;

    while let Ok((rest, pem_obj)) = x509_parser::pem::parse_x509_pem(remaining) {
        let label = pem_obj.label.to_uppercase();
        let der_data = pem_obj.contents.to_vec();

        if label.contains("CERTIFICATE REQUEST") || label.contains("CERTIFICATE-REQUEST") {
            match csr::parse_csr_der(&der_data) {
                Ok(csr) => results.push(Ok(Document::Csr(csr))),
                Err(e) => results.push(Err(format!("CSR parse error: {e}"))),
            }
        } else if label.contains("CERTIFICATE") {
            match crate::cert::parse_der_certificate(&der_data) {
                Ok(cert) => results.push(Ok(Document::Certificate(cert))),
                Err(e) => results.push(Err(format!("Certificate parse error: {e}"))),
            }
        }
        // Skip other PEM block types (private keys, etc.)

        remaining = rest;
        if remaining.is_empty() {
            break;
        }
    }

    if results.is_empty() {
        if bytes_contains_any(
            data,
            &[
                "-----BEGIN CERTIFICATE-----",
                "-----BEGIN CERTIFICATE REQUEST-----",
            ],
        ) {
            results.push(Err(
                "No valid certificate or CSR blocks found in PEM data".to_string()
            ));
        } else {
            results.push(Err("No recognized PEM blocks found in data".to_string()));
        }
    }

    results
}

fn load_der_document(data: &[u8]) -> Vec<std::result::Result<Document, String>> {
    // Try certificate first, then CSR
    if let Ok(cert) = crate::cert::parse_der_certificate(data) {
        return vec![Ok(Document::Certificate(cert))];
    }

    if let Ok(csr) = csr::parse_csr_der(data) {
        return vec![Ok(Document::Csr(csr))];
    }

    vec![Err("Failed to parse as certificate or CSR".to_string())]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_certificate_pem() {
        let pem = include_bytes!("../assets/baidu.com.pem");
        let docs = load_documents(pem);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].as_ref().unwrap().display_name().contains("baidu"));
        assert!(!docs[0].as_ref().unwrap().is_csr());
    }

    #[test]
    fn test_load_csr_pem() {
        let csr = include_bytes!("../assets/test.csr");
        let docs = load_documents(csr);
        assert_eq!(docs.len(), 1);
        assert!(docs[0].as_ref().unwrap().is_csr());
        assert_eq!(docs[0].as_ref().unwrap().display_name(), "Test Certificate");
    }

    #[test]
    fn test_load_csr_with_extensions() {
        let csr = include_bytes!("../assets/test_with_exts.csr");
        let docs = load_documents(csr);
        assert_eq!(docs.len(), 1);
        let doc = docs[0].as_ref().unwrap();
        assert!(doc.is_csr());
        let labels: Vec<&str> = doc.fields().iter().map(|f| f.label.as_str()).collect();
        assert!(labels.contains(&"Attributes"));
    }

    #[test]
    fn test_load_invalid_data() {
        let docs = load_documents(b"not a valid document");
        assert_eq!(docs.len(), 1);
        assert!(docs[0].is_err());
    }

    #[test]
    fn test_document_to_pem() {
        let csr = include_bytes!("../assets/test.csr");
        let docs = load_documents(csr);
        let doc = docs[0].as_ref().unwrap();
        let pem = doc.to_pem();
        assert!(pem.contains("CERTIFICATE REQUEST"));
    }
}
