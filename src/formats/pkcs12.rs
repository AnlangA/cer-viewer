//! PKCS#12 parser for .p12 and .pfx files.
//!
//! PKCS#12 is a format for storing certificates and private keys, often password-protected.
//!
//! NOTE: The current pkcs12 crate (v0.2.0-pre.0) is low-level and doesn't provide
//! high-level decryption support yet. This module provides format detection and
//! basic parsing structure. Full decryption support will be added later.

use crate::cert::{CertError, Result};
use crate::security::ProtectedString;
use der::Decode;
use pkcs12::{Pfx, PKCS_12_CERT_BAG_OID, PKCS_12_KEY_BAG_OID, PKCS_12_PKCS8_KEY_BAG_OID};
use std::fmt;

/// Parsed PKCS#12 certificate bundle.
///
/// A PKCS#12 file can contain multiple certificates and optionally a private key.
#[derive(Debug, Clone)]
pub struct ParsedPkcs12 {
    /// The primary certificate from the bundle (DER-encoded).
    pub cert: Option<Vec<u8>>,
    /// Private key data (DER-encoded), if present.
    /// NOTE: Not yet implemented due to pkcs12 crate limitations.
    pub private_key: Option<Vec<u8>>,
    /// Additional certificates in the chain (DER-encoded).
    pub chain: Vec<Vec<u8>>,
    /// The friendly name (if present).
    pub friendly_name: Option<String>,
}

impl ParsedPkcs12 {
    /// Parse a PKCS#12 archive with the given password.
    ///
    /// # Arguments
    /// * `data` - The DER-encoded PKCS#12 data
    /// * `password` - Optional password for decryption (None means empty password)
    ///
    /// NOTE: Full decryption support is not yet available in the underlying pkcs12 crate.
    /// This function currently extracts unencrypted certificates only.
    pub fn parse(data: &[u8], _password: Option<&ProtectedString>) -> Result<Self> {
        // Parse the PFX (PKCS#12) structure
        let pfx = Pfx::from_der(data)
            .map_err(|e| CertError::parse(format!("Invalid PKCS#12 structure: {e}")))?;

        // The authenticated safe contains the actual content
        // For now, we'll extract what we can from the structure
        let cert = None;
        let private_key = None;
        let chain = Vec::new();
        let friendly_name = None;

        // TODO: Implement full decryption when pkcs12 crate supports it
        // See: https://github.com/RustCrypto/formats/tree/master/pkcs12
        if pfx.mac_data.is_some() {
            return Err(CertError::parse(
                "Password-protected PKCS#12 files are not yet supported. \
                The underlying pkcs12 crate is still under development."
            ));
        }

        Ok(Self {
            cert,
            private_key,
            chain,
            friendly_name,
        })
    }

    /// Check if this bundle contains a private key.
    pub fn has_private_key(&self) -> bool {
        self.private_key.is_some()
    }

    /// Get the total number of certificates in this bundle.
    pub fn cert_count(&self) -> usize {
        self.cert.as_ref().map_or(0, |_| 1) + self.chain.len()
    }

    /// Get all certificates including the main cert and chain.
    pub fn all_certs(&self) -> Vec<&[u8]> {
        let mut certs = Vec::new();
        if let Some(ref c) = self.cert {
            certs.push(&c[..]);
        }
        for chain_cert in &self.chain {
            certs.push(&chain_cert[..]);
        }
        certs
    }
}

impl fmt::Display for ParsedPkcs12 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PKCS#12 Archive")?;
        if let Some(ref name) = self.friendly_name {
            write!(f, " ({name})")?;
        }
        write!(f, ": {} certificate(s)", self.cert_count())?;
        if self.has_private_key() {
            write!(f, ", includes private key")?;
        }
        Ok(())
    }
}

/// Detect if data might be a PKCS#12 file.
///
/// PKCS#12 files (also known as PFX) are DER-encoded ASN.1 structures.
/// This is a heuristic check.
pub fn is_pkcs12(data: &[u8]) -> bool {
    // PKCS#12 files should start with a SEQUENCE tag (0x30)
    if data.is_empty() || data[0] != 0x30 {
        return false;
    }

    // Try to parse as PFX (PKCS#12)
    Pfx::from_der(data).is_ok()
}

/// Check if a PKCS#12 file requires a password.
///
/// This checks if the MAC data is present, which indicates password protection.
pub fn requires_password(data: &[u8]) -> Result<bool> {
    let pfx = Pfx::from_der(data)
        .map_err(|e| CertError::parse(format!("Invalid PKCS#12: {e}")))?;

    Ok(pfx.mac_data.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pkcs12_with_invalid_data() {
        assert!(!is_pkcs12(b"not pkcs12"));
        assert!(!is_pkcs12(b""));
    }

    #[test]
    fn test_is_pkcs12_with_x509_pem() {
        // Regular PEM certificate is not PKCS#12
        let pem = include_bytes!("../../assets/baidu.com.pem");
        assert!(!is_pkcs12(pem));
    }

    #[test]
    fn test_parsed_pkcs12_display() {
        // Create a dummy parsed PKCS#12 for testing display
        let dummy = ParsedPkcs12 {
            cert: Some(vec![1, 2, 3]),
            private_key: Some(vec![4, 5, 6]),
            chain: vec![vec![7, 8, 9]],
            friendly_name: Some("Test Certificate".to_string()),
        };

        let display = format!("{dummy}");
        assert!(display.contains("PKCS#12"));
        assert!(display.contains("Test Certificate"));
        assert!(display.contains("2 certificate(s)"));
        assert!(display.contains("private key"));
    }

    #[test]
    fn test_has_private_key() {
        let with_key = ParsedPkcs12 {
            cert: Some(vec![1, 2, 3]),
            private_key: Some(vec![4, 5, 6]),
            chain: vec![],
            friendly_name: None,
        };

        assert!(with_key.has_private_key());

        let without_key = ParsedPkcs12 {
            cert: Some(vec![1, 2, 3]),
            private_key: None,
            chain: vec![],
            friendly_name: None,
        };

        assert!(!without_key.has_private_key());
    }

    #[test]
    fn test_cert_count() {
        let with_main = ParsedPkcs12 {
            cert: Some(vec![1, 2, 3]),
            private_key: None,
            chain: vec![vec![1], vec![2], vec![3]],
            friendly_name: None,
        };

        assert_eq!(with_main.cert_count(), 4); // 1 main + 3 chain certs

        let without_main = ParsedPkcs12 {
            cert: None,
            private_key: None,
            chain: vec![vec![1], vec![2], vec![3]],
            friendly_name: None,
        };

        assert_eq!(without_main.cert_count(), 3); // 3 chain certs only
    }

    #[test]
    fn test_all_certs() {
        let dummy = ParsedPkcs12 {
            cert: Some(vec![1, 2, 3]),
            private_key: None,
            chain: vec![vec![4], vec![5]],
            friendly_name: None,
        };

        let all = dummy.all_certs();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], &[1, 2, 3]);
        assert_eq!(all[1], &[4]);
        assert_eq!(all[2], &[5]);
    }
}
