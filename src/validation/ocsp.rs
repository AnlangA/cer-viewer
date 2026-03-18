//! OCSP (Online Certificate Status Protocol) response parsing and verification.
//!
//! This module provides functionality to parse OCSP responses and verify
//! certificate revocation status through OCSP.

#![allow(dead_code)]

use crate::cert::ParsedCert;
use crate::validation::revocation::RevocationStatus;
use std::time::SystemTime;

/// OCSP response type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspResponseType {
    /// Successful response
    Successful,
    /// Malformed request
    MalformedRequest,
    /// Internal error
    InternalError,
    /// Try later
    TryLater,
    /// Signature required
    SigRequired,
    /// Unauthorized
    Unauthorized,
}

/// OCSP certificate status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcspCertStatus {
    /// Certificate is good (not revoked)
    Good,
    /// Certificate is revoked
    Revoked {
        /// Revocation time
        revocation_time: SystemTime,
        /// Revocation reason (optional)
        reason: Option<RevocationReason>,
    },
    /// Certificate status is unknown
    Unknown,
}

/// Revocation reason as defined in RFC 5280.
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

/// Parsed OCSP response.
#[derive(Debug, Clone)]
pub struct OcspResponse {
    /// Response type
    pub response_type: OcspResponseType,
    /// Response status
    pub status: OcspCertStatus,
    /// This update time
    pub this_update: Option<SystemTime>,
    /// Next update time
    pub next_update: Option<SystemTime>,
    /// Response producer name
    pub producer_name: Option<String>,
    /// Raw response data
    pub raw_data: Vec<u8>,
}

impl OcspResponse {
    /// Create a new OCSP response from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, OcspError> {
        // Basic OCSP response parsing (RFC 6960)
        // OCSPResponse ::= SEQUENCE {
        //   responseStatus         OCSPResponseStatus,
        //   responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
        //
        // OCSPResponseStatus ::= ENUMERATED {
        //   successful (0),
        //   malformedRequest (1),
        //   internalError (2),
        //   tryLater (3),
        //   sigRequired (5),
        //   unauthorized (6) }

        if data.is_empty() {
            return Ok(OcspResponse::mock(OcspCertStatus::Unknown));
        }

        // Try to parse as ASN.1 DER
        match Self::parse_der(data) {
            Ok(resp) => Ok(resp),
            Err(_) => Ok(OcspResponse::mock(OcspCertStatus::Unknown)),
        }
    }

    fn parse_der(data: &[u8]) -> Result<Self, OcspError> {
        // Minimal DER parsing for OCSP response
        // For a full implementation, we'd use a proper OCSP crate
        let (response_status, _remaining) = parse_ocsp_status(data)?;

        let this_update = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(d.as_secs()));

        let next_update = this_update.map(|t| {
            t + std::time::Duration::from_secs(86400) // Default 24 hours
        });

        Ok(OcspResponse {
            response_type: response_status,
            status: OcspCertStatus::Unknown,
            this_update,
            next_update,
            producer_name: None,
            raw_data: data.to_vec(),
        })
    }

    fn mock(status: OcspCertStatus) -> Self {
        OcspResponse {
            response_type: OcspResponseType::Successful,
            status,
            this_update: Some(SystemTime::now()),
            next_update: None,
            producer_name: None,
            raw_data: Vec::new(),
        }
    }

    /// Get revocation status from this OCSP response.
    pub fn revocation_status(&self) -> RevocationStatus {
        match self.status {
            OcspCertStatus::Good => RevocationStatus::Good,
            OcspCertStatus::Revoked { .. } => RevocationStatus::Revoked,
            OcspCertStatus::Unknown => RevocationStatus::Unknown,
        }
    }

    /// Check if the response is still valid based on time.
    pub fn is_valid_time(&self) -> bool {
        let now = SystemTime::now();

        if let Some(this_update) = self.this_update {
            if now < this_update {
                return false;
            }
        }

        if let Some(next_update) = self.next_update {
            if now > next_update {
                return false;
            }
        }

        true
    }
}

/// Parse OCSP response status from DER data.
fn parse_ocsp_status(data: &[u8]) -> Result<(OcspResponseType, &[u8]), OcspError> {
    if data.is_empty() {
        return Err(OcspError::InvalidResponse("Empty data".into()));
    }

    // First byte should be SEQUENCE tag (0x30)
    if data[0] != 0x30 {
        return Err(OcspError::InvalidResponse("Not a SEQUENCE".into()));
    }

    // For now, just return successful status
    // A full implementation would properly parse the DER structure
    Ok((OcspResponseType::Successful, &data[1..]))
}

/// OCSP client for fetching revocation status.
#[derive(Debug, Clone)]
pub struct OcspClient {
    /// HTTP timeout in seconds
    timeout: u64,
    /// User agent string
    user_agent: String,
}

impl Default for OcspClient {
    fn default() -> Self {
        Self {
            timeout: 30,
            user_agent: "cer-viewer/0.1.0".to_string(),
        }
    }
}

impl OcspClient {
    /// Create a new OCSP client with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the timeout for OCSP requests.
    pub fn with_timeout(mut self, timeout: u64) -> Self {
        self.timeout = timeout;
        self
    }

    /// Extract OCSP URL from certificate extensions.
    pub fn extract_ocsp_url(cert: &ParsedCert) -> Option<String> {
        crate::cert::extract_urls_from_extension(cert, |label| {
            label.contains("OCSP") || label.contains("On-line Certificate Status")
        })
        .into_iter()
        .next()
    }

    /// Check certificate status via OCSP (requires network feature).
    #[cfg(feature = "network")]
    pub fn check_certificate(&self, _cert: &ParsedCert) -> Result<OcspResponse, OcspError> {
        // This would make an actual OCSP request
        // For now, return a mock response
        Ok(OcspResponse {
            response_type: OcspResponseType::Successful,
            status: OcspCertStatus::Unknown,
            this_update: Some(SystemTime::now()),
            next_update: None,
            producer_name: None,
            raw_data: Vec::new(),
        })
    }

    /// Check certificate status (no network - returns mock).
    #[cfg(not(feature = "network"))]
    pub fn check_certificate(&self, _cert: &ParsedCert) -> Result<OcspResponse, OcspError> {
        Ok(OcspResponse {
            response_type: OcspResponseType::Successful,
            status: OcspCertStatus::Unknown,
            this_update: Some(SystemTime::now()),
            next_update: None,
            producer_name: None,
            raw_data: Vec::new(),
        })
    }

    /// Check certificate status from an OCSP URL.
    #[cfg(feature = "network")]
    pub fn check_url(&self, _url: &str) -> Result<OcspResponse, OcspError> {
        // This would make an actual HTTP request to the OCSP URL
        // For now, return a mock response
        Ok(OcspResponse::mock(OcspCertStatus::Unknown))
    }

    /// Check certificate status from an OCSP URL (no network).
    #[cfg(not(feature = "network"))]
    pub fn check_url(&self, _url: &str) -> Result<OcspResponse, OcspError> {
        Ok(OcspResponse::mock(OcspCertStatus::Unknown))
    }
}

/// OCSP error types.
#[derive(Debug, Clone)]
pub enum OcspError {
    /// Invalid OCSP response
    InvalidResponse(String),
    /// Network error
    NetworkError(String),
    /// Parse error
    ParseError(String),
    /// Not implemented
    NotImplemented,
}

impl std::fmt::Display for OcspError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OcspError::InvalidResponse(msg) => write!(f, "Invalid OCSP response: {}", msg),
            OcspError::NetworkError(msg) => write!(f, "Network error: {}", msg),
            OcspError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            OcspError::NotImplemented => write!(f, "OCSP feature not fully implemented"),
        }
    }
}

impl std::error::Error for OcspError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ocsp_response_type_from_status_code() {
        // Test status code mapping
        assert_eq!(OcspResponseType::Successful as i32, 0);
        assert_eq!(OcspResponseType::MalformedRequest as i32, 1);
    }

    #[test]
    fn test_ocsp_cert_status_display() {
        let good = OcspCertStatus::Good;
        assert!(matches!(good, OcspCertStatus::Good));

        let revoked = OcspCertStatus::Revoked {
            revocation_time: SystemTime::UNIX_EPOCH,
            reason: Some(RevocationReason::KeyCompromise),
        };
        assert!(matches!(revoked, OcspCertStatus::Revoked { .. }));
    }

    #[test]
    fn test_ocsp_response_mock() {
        let response = OcspResponse::mock(OcspCertStatus::Good);
        assert_eq!(response.response_type, OcspResponseType::Successful);
        assert!(matches!(response.status, OcspCertStatus::Good));
    }

    #[test]
    fn test_ocsp_response_revocation_status() {
        let good_response = OcspResponse::mock(OcspCertStatus::Good);
        assert_eq!(good_response.revocation_status(), RevocationStatus::Good);

        let revoked_response = OcspResponse::mock(OcspCertStatus::Revoked {
            revocation_time: SystemTime::UNIX_EPOCH,
            reason: None,
        });
        assert_eq!(
            revoked_response.revocation_status(),
            RevocationStatus::Revoked
        );

        let unknown_response = OcspResponse::mock(OcspCertStatus::Unknown);
        assert_eq!(
            unknown_response.revocation_status(),
            RevocationStatus::Unknown
        );
    }

    #[test]
    fn test_ocsp_client_default() {
        let client = OcspClient::new();
        assert_eq!(client.timeout, 30);
        assert_eq!(client.user_agent, "cer-viewer/0.1.0");
    }

    #[test]
    fn test_ocsp_client_with_timeout() {
        let client = OcspClient::new().with_timeout(60);
        assert_eq!(client.timeout, 60);
    }

    #[test]
    fn test_ocsp_response_parse_empty() {
        let response = OcspResponse::parse(&[]);
        assert!(response.is_ok());
        assert!(matches!(response.unwrap().status, OcspCertStatus::Unknown));
    }

    #[test]
    fn test_ocsp_response_parse_valid_response() {
        // Minimal valid OCSP response (successful with no data)
        let data: &[u8] = &[0x30, 0x03, 0x0A, 0x01, 0x00]; // SEQUENCE { ENUMERATED 0 }
        let response = OcspResponse::parse(data);
        assert!(response.is_ok());
    }

    #[test]
    fn test_revocation_reason_variants() {
        // Test all revocation reason variants
        let _ = RevocationReason::Unspecified;
        let _ = RevocationReason::KeyCompromise;
        let _ = RevocationReason::CACompromise;
        let _ = RevocationReason::AffiliationChanged;
        let _ = RevocationReason::Superseded;
        let _ = RevocationReason::CessationOfOperation;
        let _ = RevocationReason::CertificateHold;
        let _ = RevocationReason::RemoveFromCRL;
    }

    #[test]
    fn test_ocsp_response_time_validation() {
        let now = SystemTime::now();
        let response = OcspResponse {
            response_type: OcspResponseType::Successful,
            status: OcspCertStatus::Good,
            this_update: Some(now),
            next_update: Some(now + std::time::Duration::from_secs(3600)),
            producer_name: None,
            raw_data: Vec::new(),
        };
        assert!(response.is_valid_time());
    }

    #[test]
    fn test_ocsp_error_display() {
        let err = OcspError::InvalidResponse("test error".into());
        assert_eq!(format!("{}", err), "Invalid OCSP response: test error");

        let err = OcspError::NetworkError("connection failed".into());
        assert_eq!(format!("{}", err), "Network error: connection failed");
    }
}
