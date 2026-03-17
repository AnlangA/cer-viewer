//! CMS/PKCS#7 parser for certificate chains.
//!
//! This module handles PKCS#7/CMS formatted files, typically .p7b or .p7c files,
//! which contain certificate chains without private keys.

use crate::cert::{CertError, Result};
use der::{Decode, Encode};
// The cms crate is re-exported by pkcs12
use pkcs12::cms::content_info::ContentInfo;
use pkcs12::cms::signed_data::SignedData;
use pkcs12::cms::cert::CertificateChoices;
use std::fmt;

/// Parsed CMS/PKCS#7 certificate data.
///
/// A CMS file typically contains a certificate chain without private keys.
#[derive(Debug, Clone)]
pub struct ParsedCms {
    /// Certificates extracted from the CMS structure (DER-encoded).
    pub certificates: Vec<Vec<u8>>,
    /// The content type OID (e.g., SIGNED_DATA)
    pub content_type: String,
}

impl ParsedCms {
    /// Parse a CMS/PKCS#7 file.
    ///
    /// # Arguments
    /// * `data` - The DER-encoded CMS data
    pub fn parse(data: &[u8]) -> Result<Self> {
        // Parse as ContentInfo
        let content_info = ContentInfo::from_der(data)
            .map_err(|e| CertError::parse(format!("Invalid CMS/PKCS#7: {e}")))?;

        // Get the content type OID as a string
        let content_type = content_info.content_type.to_string();

        // Check if this is SignedData (most common for cert chains)
        // OID for signedData: 1.2.840.113549.1.7.2
        let signed_data_oid = [42, 134, 72, 134, 247, 13, 1, 7, 2];
        let certificates = if content_info.content_type.as_bytes() == signed_data_oid {
            self::extract_signed_data_certs(&content_info)?
        } else {
            // For other content types, return empty
            Vec::new()
        };

        Ok(Self {
            certificates,
            content_type,
        })
    }

    /// Get the number of certificates in this CMS structure.
    pub fn cert_count(&self) -> usize {
        self.certificates.len()
    }

    /// Check if this CMS structure contains any certificates.
    pub fn has_certificates(&self) -> bool {
        !self.certificates.is_empty()
    }

    /// Get all certificates as DER byte slices.
    pub fn all_certs(&self) -> Vec<&[u8]> {
        self.certificates.iter().map(|c| c.as_slice()).collect()
    }
}

impl fmt::Display for ParsedCms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CMS/PKCS#7 Archive: {} certificate(s)", self.cert_count())
    }
}

/// Extract certificates from a SignedData content.
fn extract_signed_data_certs(content_info: &ContentInfo) -> Result<Vec<Vec<u8>>> {
    // Decode the content as SignedData
    let signed_data = SignedData::from_der(content_info.content.value())
        .map_err(|e| CertError::parse(format!("Invalid SignedData: {e}")))?;

    let mut certificates = Vec::new();

    // Extract certificates from the CertificateSet if present
    if let Some(cert_set) = &signed_data.certificates {
        for cert_choice in cert_set.0.iter() {
            // CertificateChoices can be a Certificate or other types
            // We extract the raw DER bytes by encoding the choice
            let der_bytes = match cert_choice {
                CertificateChoices::Certificate(cert) => {
                    cert.to_der()
                        .map_err(|e| CertError::parse(format!("Failed to encode certificate: {e}")))
                }
                // Handle other certificate choices as needed
                _ => continue,
            }?;
            certificates.push(der_bytes);
        }
    }

    Ok(certificates)
}

/// Detect if data might be a CMS/PKCS#7 file.
///
/// CMS files are DER-encoded ASN.1 structures starting with a SEQUENCE tag.
pub fn is_cms(data: &[u8]) -> bool {
    // CMS files should start with a SEQUENCE tag (0x30)
    if data.is_empty() || data[0] != 0x30 {
        return false;
    }

    // Try to parse as ContentInfo
    ContentInfo::from_der(data).is_ok()
}

/// Check if a PEM file might be a CMS/PKCS#7 file.
pub fn is_pem_cms(data: &[u8]) -> bool {
    let content = String::from_utf8_lossy(data);
    content.contains("PKCS7") ||
    content.contains("PKCS#7") ||
    content.contains("CMS") ||
    content.contains("CERTIFICATE BAG")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_cms_with_invalid_data() {
        assert!(!is_cms(b"not cms"));
        assert!(!is_cms(b""));
    }

    #[test]
    fn test_is_cms_with_x509_pem() {
        // Regular PEM certificate is not CMS
        let pem = include_bytes!("../../assets/baidu.com.pem");
        assert!(!is_cms(pem));
    }

    #[test]
    fn test_is_pem_cms_with_regular_cert() {
        let pem = include_bytes!("../../assets/baidu.com.pem");
        assert!(!is_pem_cms(pem));
    }

    #[test]
    fn test_is_pem_cms_with_p7b_header() {
        let p7b = b"-----BEGIN PKCS7-----";
        assert!(is_pem_cms(p7b));
    }

    #[test]
    fn test_parsed_cms_display() {
        let dummy = ParsedCms {
            certificates: vec![vec![1, 2, 3], vec![4, 5, 6]],
            content_type: "1.2.840.113549.1.7.2".to_string(),
        };

        let display = format!("{dummy}");
        assert!(display.contains("CMS/PKCS#7"));
        assert!(display.contains("2 certificate(s)"));
    }

    #[test]
    fn test_cert_count() {
        let empty = ParsedCms {
            certificates: vec![],
            content_type: "test".to_string(),
        };
        assert_eq!(empty.cert_count(), 0);
        assert!(!empty.has_certificates());

        let with_certs = ParsedCms {
            certificates: vec![vec![1], vec![2], vec![3]],
            content_type: "test".to_string(),
        };
        assert_eq!(with_certs.cert_count(), 3);
        assert!(with_certs.has_certificates());
    }

    #[test]
    fn test_all_certs() {
        let dummy = ParsedCms {
            certificates: vec![vec![1, 2, 3], vec![4, 5, 6]],
            content_type: "test".to_string(),
        };

        let all = dummy.all_certs();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], &[1, 2, 3]);
        assert_eq!(all[1], &[4, 5, 6]);
    }
}
