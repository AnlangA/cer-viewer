//! Format detection and handling.
//!
//! This module provides utilities for detecting the format of certificate
//! and key files from their content.

#![allow(dead_code)]

use crate::utils;

/// Detected file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// PEM encoded data
    Pem,
    /// DER encoded binary data
    Der,
    /// PKCS#12 container
    Pkcs12,
    /// PKCS#7/CMS container
    Cms,
    /// Unknown format
    Unknown,
}

/// Detect the format of certificate/key data.
pub fn detect_format(data: &[u8]) -> FileFormat {
    // Check for PEM format (starts with -----BEGIN)
    if data.starts_with(b"-----BEGIN") {
        // Further classify by content type (using byte comparison to avoid allocation)
        if utils::bytes_contains_any(data, &["PKCS12", "PKCS-12", "PKCS#12"]) {
            return FileFormat::Pkcs12;
        }
        if utils::bytes_contains_any(data, &["PKCS7", "PKCS-7", "PKCS#7"]) {
            return FileFormat::Cms;
        }
        return FileFormat::Pem;
    }

    // DER-encoded ASN.1 data starts with SEQUENCE tag (0x30)
    // PKCS#12 and CMS also start with a SEQUENCE, so we need to check
    if !data.is_empty() && data[0] == 0x30 {
        #[cfg(feature = "pkcs12")]
        {
            // Try to detect PKCS#12 first
            if crate::formats::pkcs12::is_pkcs12(data) {
                return FileFormat::Pkcs12;
            }
            // Try to detect CMS
            if crate::formats::cms::is_cms(data) {
                return FileFormat::Cms;
            }
        }
        return FileFormat::Der;
    }

    FileFormat::Unknown
}

/// Check if data looks like a PEM-encoded certificate.
pub fn is_pem_certificate(data: &[u8]) -> bool {
    utils::bytes_contains(data, "-----BEGIN CERTIFICATE-----")
}

/// Check if data looks like a PEM-encoded private key.
pub fn is_pem_private_key(data: &[u8]) -> bool {
    utils::bytes_contains_any(
        data,
        &[
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN EC PARAMETERS-----",
        ],
    )
}

/// Check if data looks like a PEM-encoded PKCS#8 key.
pub fn is_pem_pkcs8_key(data: &[u8]) -> bool {
    utils::bytes_contains_any(
        data,
        &[
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_pem_format() {
        let pem = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
        assert_eq!(detect_format(pem), FileFormat::Pem);
    }

    #[test]
    fn test_detect_der_format() {
        // DER ASN.1 SEQUENCE tag
        let der: &[u8] = &[0x30, 0x82, 0x01, 0x00];
        assert_eq!(detect_format(der), FileFormat::Der);
    }

    #[test]
    fn test_detect_unknown_format() {
        let unknown = b"not a certificate";
        assert_eq!(detect_format(unknown), FileFormat::Unknown);
    }

    #[test]
    fn test_is_pem_certificate() {
        let cert = b"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----";
        assert!(is_pem_certificate(cert));
    }

    #[test]
    fn test_is_pem_private_key() {
        let key = b"-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----";
        assert!(is_pem_private_key(key));
    }
}
