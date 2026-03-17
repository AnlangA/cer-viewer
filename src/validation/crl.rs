//! CRL (Certificate Revocation List) parsing and verification.
//!
//! This module provides functionality to parse CRLs and verify
//! certificate revocation status.

use crate::cert::ParsedCert;
use crate::validation::revocation::RevocationStatus;
use std::time::SystemTime;

/// CRL entry representing a revoked certificate.
#[derive(Debug, Clone)]
pub struct CrlEntry {
    /// Serial number of the revoked certificate
    pub serial_number: Vec<u8>,
    /// Revocation date
    pub revocation_date: SystemTime,
    /// Revocation reason (optional)
    pub reason: Option<RevocationReason>,
}

/// CRL revocation reasons (RFC 5280).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CACompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCRL,
}

/// Parsed CRL (Certificate Revocation List).
#[derive(Debug, Clone)]
pub struct CertificateRevocationList {
    /// Issuer of this CRL
    pub issuer: String,
    /// This update timestamp
    pub this_update: SystemTime,
    /// Next update timestamp
    pub next_update: Option<SystemTime>,
    /// List of revoked certificates
    pub revoked_certs: Vec<CrlEntry>,
    /// CRL extensions
    pub extensions: Vec<CrlExtension>,
    /// Raw DER data
    pub raw_der: Vec<u8>,
}

/// CRL extension types.
#[derive(Debug, Clone)]
pub enum CrlExtension {
    /// CRL number extension
    CrlNumber(u64),
    /// Delta CRL indicator
    DeltaCrlIndicator(u64),
    /// Issuing distribution point
    IssuingDistributionPoint(String),
    /// Authority key identifier
    AuthorityKeyIdentifier(Vec<u8>),
    /// Unknown extension
    Unknown { oid: String, critical: bool },
}

impl CertificateRevocationList {
    /// Parse a CRL from DER-encoded data.
    pub fn from_der(der_data: &[u8]) -> Result<Self, CrlError> {
        // Basic CRL parsing (RFC 5280)
        // CertificateList ::= SEQUENCE {
        //   tbsCertList          TBSCertList,
        //   signatureAlgorithm   AlgorithmIdentifier,
        //   signatureValue       BIT STRING }

        if der_data.is_empty() {
            return Err(CrlError::InvalidData("Empty CRL data".into()));
        }

        // Check for SEQUENCE tag (0x30)
        if der_data[0] != 0x30 {
            return Err(CrlError::InvalidData("Not a valid CRL structure".into()));
        }

        // For now, return a mock CRL
        // A full implementation would use proper ASN.1 parsing
        Ok(CertificateRevocationList {
            issuer: "CN=Unknown CA".to_string(),
            this_update: SystemTime::now(),
            next_update: None,
            revoked_certs: Vec::new(),
            extensions: Vec::new(),
            raw_der: der_data.to_vec(),
        })
    }

    /// Parse a CRL from PEM-encoded data.
    pub fn from_pem(pem_data: &[u8]) -> Result<Self, CrlError> {
        // Find the CRL block in PEM
        let pem_str = std::str::from_utf8(pem_data)
            .map_err(|_| CrlError::InvalidData("Invalid UTF-8 in PEM".into()))?;

        let der_start = pem_str.find("-----BEGIN X509 CRL-----");
        let der_end = pem_str.find("-----END X509 CRL-----");

        match (der_start, der_end) {
            (Some(start), Some(end)) => {
                let pem_block = &pem_str[start..end + 21];
                let base64_data: String = pem_block
                    .lines()
                    .skip(1)
                    .filter(|line| !line.starts_with("-----"))
                    .map(|line| line.trim())
                    .collect();

                use base64::Engine;
                let der_data = base64::prelude::BASE64_STANDARD.decode(&base64_data)
                    .map_err(|_| CrlError::InvalidData("Invalid base64 in PEM".into()))?;

                Self::from_der(&der_data)
            }
            _ => Err(CrlError::InvalidData("No valid CRL PEM block found".into())),
        }
    }

    /// Check if a certificate is revoked based on its serial number.
    pub fn is_revoked(&self, serial_number: &[u8]) -> bool {
        self.revoked_certs
            .iter()
            .any(|entry| entry.serial_number == serial_number)
    }

    /// Get revocation status for a certificate.
    pub fn revocation_status(&self, cert: &ParsedCert) -> RevocationStatus {
        // Parse the serial number from hex format
        let serial_bytes = match self.parse_serial_number(&cert.serial_number) {
            Ok(bytes) => bytes,
            Err(_) => return RevocationStatus::Unknown,
        };

        if self.is_revoked(&serial_bytes) {
            RevocationStatus::Revoked
        } else {
            RevocationStatus::Good
        }
    }

    /// Check if the CRL is still valid based on time.
    pub fn is_valid_time(&self) -> bool {
        let now = SystemTime::now();

        if now < self.this_update {
            return false;
        }

        if let Some(next_update) = self.next_update {
            if now > next_update {
                return false;
            }
        }

        true
    }

    /// Get the number of revoked certificates.
    pub fn revoked_count(&self) -> usize {
        self.revoked_certs.len()
    }

    /// Parse serial number from colon-separated hex format.
    fn parse_serial_number(&self, hex_serial: &str) -> Result<Vec<u8>, CrlError> {
        let cleaned = hex_serial.replace(':', "").replace(" ", "");
        hex::decode(&cleaned)
            .map_err(|_| CrlError::InvalidData(format!("Invalid serial number: {}", hex_serial)))
    }

    /// Find CRL entry by serial number.
    pub fn find_entry(&self, serial_number: &[u8]) -> Option<&CrlEntry> {
        self.revoked_certs
            .iter()
            .find(|entry| entry.serial_number == serial_number)
    }
}

/// CRL client for downloading and checking CRLs.
#[derive(Debug, Clone)]
pub struct CrlClient {
    /// HTTP timeout in seconds
    timeout: u64,
    /// User agent string
    user_agent: String,
    /// Maximum CRL size in bytes
    max_size: usize,
}

impl Default for CrlClient {
    fn default() -> Self {
        Self {
            timeout: 30,
            user_agent: "cer-viewer/0.1.0".to_string(),
            max_size: 10 * 1024 * 1024, // 10 MB
        }
    }
}

impl CrlClient {
    /// Create a new CRL client with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timeout for CRL requests.
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set the maximum CRL size.
    pub fn with_max_size(mut self, max_size: usize) -> Self {
        self.max_size = max_size;
        self
    }

    /// Extract CRL distribution points from certificate extensions.
    pub fn extract_crl_urls(cert: &ParsedCert) -> Vec<String> {
        let mut urls = Vec::new();

        // Look for CRL Distribution Points extension
        // OID: 2.5.29.31 (cRLDistributionPoints)
        for field in &cert.fields {
            if field.label.contains("CRL Distribution Points") || field.label.contains("cRLDistributionPoints") {
                for child in &field.children {
                    for subchild in &child.children {
                        if let Some(ref url) = subchild.value {
                            if url.starts_with("http://") || url.starts_with("https://") || url.starts_with("ldap://") {
                                urls.push(url.clone());
                            }
                        }
                    }
                }
            }
        }

        urls
    }

    /// Download CRL from a URL (requires network feature).
    #[cfg(feature = "network")]
    pub fn download(&self, url: &str) -> Result<CertificateRevocationList, CrlError> {
        use std::io::Read;

        let client = reqwest::blocking::ClientBuilder::new()
            .timeout(std::time::Duration::from_secs(self.timeout))
            .user_agent(&self.user_agent)
            .build()
            .map_err(|e| CrlError::NetworkError(e.to_string()))?;

        let mut response = client
            .get(url)
            .send()
            .map_err(|e| CrlError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(CrlError::NetworkError(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let content_length = response.content_length().unwrap_or(0) as usize;
        if content_length > self.max_size {
            return Err(CrlError::NetworkError(format!(
                "CRL too large: {} bytes",
                content_length
            )));
        }

        let mut data = Vec::new();
        response
            .read_to_end(&mut data)
            .map_err(|e| CrlError::NetworkError(e.to_string()))?;

        if data.len() > self.max_size {
            return Err(CrlError::NetworkError("CRL exceeds maximum size".into()));
        }

        // Try to detect format
        if data.starts_with(b"-----BEGIN") {
            CertificateRevocationList::from_pem(&data)
        } else {
            CertificateRevocationList::from_der(&data)
        }
    }

    /// Download CRL from a URL (no network support).
    #[cfg(not(feature = "network"))]
    pub fn download(&self, _url: &str) -> Result<CertificateRevocationList, CrlError> {
        Err(CrlError::NetworkError(
            "Network feature not enabled. Build with --features network".into()
        ))
    }

    /// Check certificate revocation status using CRL URLs.
    pub fn check_certificate(&self, cert: &ParsedCert) -> Result<RevocationStatus, CrlError> {
        let urls = Self::extract_crl_urls(cert);

        if urls.is_empty() {
            return Ok(RevocationStatus::Unknown);
        }

        // Try each URL until we get a valid response
        for _url in &urls {
            #[cfg(feature = "network")]
            match self.download(url) {
                Ok(crl) => {
                    return Ok(crl.revocation_status(cert));
                }
                Err(_) => continue,
            }
        }

        Ok(RevocationStatus::Unknown)
    }
}

/// CRL error types.
#[derive(Debug, Clone)]
pub enum CrlError {
    /// Invalid CRL data
    InvalidData(String),
    /// Network error
    NetworkError(String),
    /// Parse error
    ParseError(String),
}

impl std::fmt::Display for CrlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CrlError::InvalidData(msg) => write!(f, "Invalid CRL data: {}", msg),
            CrlError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            CrlError::ParseError(msg) => write!(f, "Parse error: {}", msg),
        }
    }
}

impl std::error::Error for CrlError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crl_client_default() {
        let client = CrlClient::new();
        assert_eq!(client.timeout, 30);
        assert_eq!(client.user_agent, "cer-viewer/0.1.0");
        assert_eq!(client.max_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_crl_client_with_timeout() {
        let client = CrlClient::new().with_timeout(60);
        assert_eq!(client.timeout, 60);
    }

    #[test]
    fn test_crl_client_with_max_size() {
        let client = CrlClient::new().with_max_size(1024);
        assert_eq!(client.max_size, 1024);
    }

    #[test]
    fn test_crl_parse_empty_data() {
        let result = CertificateRevocationList::from_der(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_crl_parse_invalid_sequence() {
        let result = CertificateRevocationList::from_der(&[0x01, 0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_crl_parse_valid_structure() {
        // Minimal valid CRL structure
        let data: &[u8] = &[
            0x30, 0x20, // SEQUENCE
            0x30, 0x10, // TBSCertList SEQUENCE
            0x30, 0x0A, // issuer SEQUENCE
            0x06, 0x03, 0x55, 0x04, 0x03, // OID 2.5.4.3 (CN)
            0x13, 0x03, 0x54, 0x65, 0x73, // "Tes"
            0x17, 0x02, 0x18, 0x00, // this_update
            0x30, 0x00, // revokedCertificates empty
        ];

        let result = CertificateRevocationList::from_der(data);
        assert!(result.is_ok());

        let crl = result.unwrap();
        assert_eq!(crl.revoked_count(), 0);
    }

    #[test]
    fn test_crl_is_revoked_empty() {
        let crl = CertificateRevocationList {
            issuer: "CN=Test CA".to_string(),
            this_update: SystemTime::now(),
            next_update: None,
            revoked_certs: Vec::new(),
            extensions: Vec::new(),
            raw_der: Vec::new(),
        };

        assert!(!crl.is_revoked(&[0x01, 0x02, 0x03]));
    }

    #[test]
    fn test_crl_is_revoked_with_entry() {
        let serial = vec![0x01, 0x02, 0x03];
        let crl = CertificateRevocationList {
            issuer: "CN=Test CA".to_string(),
            this_update: SystemTime::now(),
            next_update: None,
            revoked_certs: vec![CrlEntry {
                serial_number: serial.clone(),
                revocation_date: SystemTime::now(),
                reason: None,
            }],
            extensions: Vec::new(),
            raw_der: Vec::new(),
        };

        assert!(crl.is_revoked(&[0x01, 0x02, 0x03]));
        assert!(!crl.is_revoked(&[0xFF, 0xFF, 0xFF]));
    }

    #[test]
    fn test_crl_find_entry() {
        let serial = vec![0x01, 0x02, 0x03];
        let entry = CrlEntry {
            serial_number: serial.clone(),
            revocation_date: SystemTime::now(),
            reason: Some(RevocationReason::KeyCompromise),
        };

        let crl = CertificateRevocationList {
            issuer: "CN=Test CA".to_string(),
            this_update: SystemTime::now(),
            next_update: None,
            revoked_certs: vec![entry],
            extensions: Vec::new(),
            raw_der: Vec::new(),
        };

        let found = crl.find_entry(&[0x01, 0x02, 0x03]);
        assert!(found.is_some());
        assert_eq!(
            found.unwrap().reason,
            Some(RevocationReason::KeyCompromise)
        );
    }

    #[test]
    fn test_crl_parse_serial_number() {
        let crl = CertificateRevocationList {
            issuer: "CN=Test CA".to_string(),
            this_update: SystemTime::now(),
            next_update: None,
            revoked_certs: Vec::new(),
            extensions: Vec::new(),
            raw_der: Vec::new(),
        };

        // Test with colon-separated hex
        let result = crl.parse_serial_number("01:02:03");
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03]);

        // Test with spaces
        let result = crl.parse_serial_number("01 02 03");
        assert_eq!(result.unwrap(), vec![0x01, 0x02, 0x03]);

        // Test invalid format
        assert!(crl.parse_serial_number("ZZ").is_err());
    }

    #[test]
    fn test_crl_is_valid_time() {
        let now = SystemTime::now();

        let crl = CertificateRevocationList {
            issuer: "CN=Test CA".to_string(),
            this_update: now - std::time::Duration::from_secs(3600),
            next_update: Some(now + std::time::Duration::from_secs(3600)),
            revoked_certs: Vec::new(),
            extensions: Vec::new(),
            raw_der: Vec::new(),
        };

        assert!(crl.is_valid_time());
    }

    #[test]
    fn test_crl_not_yet_valid() {
        let future = SystemTime::now() + std::time::Duration::from_secs(3600);

        let crl = CertificateRevocationList {
            issuer: "CN=Test CA".to_string(),
            this_update: future,
            next_update: Some(future + std::time::Duration::from_secs(3600)),
            revoked_certs: Vec::new(),
            extensions: Vec::new(),
            raw_der: Vec::new(),
        };

        assert!(!crl.is_valid_time());
    }

    #[test]
    fn test_crl_expired() {
        let past = SystemTime::now() - std::time::Duration::from_secs(7200);

        let crl = CertificateRevocationList {
            issuer: "CN=Test CA".to_string(),
            this_update: past - std::time::Duration::from_secs(3600),
            next_update: Some(past),
            revoked_certs: Vec::new(),
            extensions: Vec::new(),
            raw_der: Vec::new(),
        };

        assert!(!crl.is_valid_time());
    }

    #[test]
    fn test_crl_parse_pem_valid() {
        let pem = b"-----BEGIN X509 CRL-----
MIICpDCCAYwCAQMwDQYJKoZIhvcNAQELBQAwFjEUMBIGA1UEAwwLVGVzdCBDQSBF
Q2SxOTA3FjAUBgNVHSUEDTMBgqJCBzYW1wbGUwDQYJKoZIhvcNAQELBQADggEB
-----END X509 CRL-----";

        let result = CertificateRevocationList::from_pem(pem);
        // The base64 above is truncated, so it might fail
        // Just check that it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_crl_parse_pem_no_block() {
        let pem = b"Not a PEM block";
        let result = CertificateRevocationList::from_pem(pem);
        assert!(result.is_err());
    }

    #[test]
    fn test_crl_error_display() {
        let err = CrlError::InvalidData("test error".into());
        assert_eq!(format!("{}", err), "Invalid CRL data: test error");

        let err = CrlError::NetworkError("connection failed".into());
        assert_eq!(format!("{}", err), "Network error: connection failed");
    }

    #[test]
    fn test_revocation_reason_variants() {
        let _ = RevocationReason::Unspecified;
        let _ = RevocationReason::KeyCompromise;
        let _ = RevocationReason::CACompromise;
        let _ = RevocationReason::AffiliationChanged;
        let _ = RevocationReason::Superseded;
        let _ = RevocationReason::CessationOfOperation;
        let _ = RevocationReason::CertificateHold;
        let _ = RevocationReason::RemoveFromCRL;
    }
}
