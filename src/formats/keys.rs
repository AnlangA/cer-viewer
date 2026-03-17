//! Private key parser for various key formats.
//!
//! This module handles PEM and DER encoded private keys including:
//! - PKCS#8 (universal private key format)
//! - SEC1 (EC private keys)
//! - RSA private keys (traditional PKCS#1)

#![allow(dead_code)]

use crate::cert::Result;
use der::Decode;
use std::fmt;

/// Type of private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// RSA private key
    Rsa,
    /// Elliptic Curve private key
    Ec,
    /// DSA private key
    Dsa,
    /// Unknown key type
    Unknown,
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Rsa => write!(f, "RSA"),
            KeyType::Ec => write!(f, "EC"),
            KeyType::Dsa => write!(f, "DSA"),
            KeyType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Parsed private key information.
///
/// This struct contains parsed information about a private key.
/// Note: The actual key material is NOT stored to prevent accidental leakage.
#[derive(Debug, Clone)]
pub struct ParsedPrivateKey {
    /// Type of the key
    pub key_type: KeyType,
    /// Key algorithm OID
    pub algorithm_oid: String,
    /// Curve name (for EC keys)
    pub curve_name: Option<String>,
    /// Key size in bits
    pub key_size: Option<usize>,
    /// Whether this key is encrypted (password protected)
    pub is_encrypted: bool,
    /// Format of the key (PEM/DER)
    pub format: KeyFormat,
}

/// Key format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFormat {
    /// PEM encoded
    Pem,
    /// DER encoded
    Der,
}

impl ParsedPrivateKey {
    /// Parse a private key from DER data.
    ///
    /// # Arguments
    /// * `data` - The DER-encoded private key data
    pub fn from_der(data: &[u8]) -> Result<Self> {
        // Try to detect the key type by examining the DER structure
        let key_type = Self::detect_key_type_from_der(data)?;

        Ok(Self {
            key_type,
            algorithm_oid: Self::get_algorithm_oid(&key_type),
            curve_name: None,
            key_size: Some(data.len() * 8), // Approximate size
            is_encrypted: false,
            format: KeyFormat::Der,
        })
    }

    /// Parse a private key from PEM data.
    ///
    /// # Arguments
    /// * `pem_data` - The PEM-encoded private key data
    pub fn from_pem(pem_data: &[u8]) -> Result<Self> {
        // Check for various PEM headers (using byte comparison to avoid allocation)
        let is_encrypted = crate::utils::bytes_contains(pem_data, "ENCRYPTED");
        let is_rsa = crate::utils::bytes_contains(pem_data, "-----BEGIN RSA PRIVATE KEY-----");
        let is_ec = crate::utils::bytes_contains_any(
            pem_data,
            &["-----BEGIN EC PRIVATE KEY-----", "-----BEGIN EC PARAMETERS-----"],
        );

        // Extract DER from PEM
        let der_data = Self::extract_der_from_pem(pem_data)?;

        // Parse based on type
        let mut key = Self::from_der(&der_data)?;

        key.is_encrypted = is_encrypted;
        key.format = KeyFormat::Pem;

        // Override type detection for explicit key types
        if is_rsa {
            key.key_type = KeyType::Rsa;
        }
        if is_ec {
            key.key_type = KeyType::Ec;
        }

        Ok(key)
    }

    /// Detect key type from DER data.
    fn detect_key_type_from_der(data: &[u8]) -> Result<KeyType> {
        // Try PKCS#8 first - check for SEQUENCE tag at start
        if !data.is_empty() && data[0] == 0x30 {
            // Try to parse as PKCS#8 PrivateKeyInfo
            // PKCS#8 starts with: SEQUENCE { version INTEGER, ... }
            if data.len() > 4 {
                // PKCS#8 structure: version is usually 0 (one byte)
                // After SEQUENCE tag and length, we should have INTEGER tag (0x02) then length (0x01) then value (0x00)
                if data.len() > 5 && data[4] == 0x02 && data[5] == 0x01 && data[6] == 0x00 {
                    // This looks like PKCS#8, try to extract algorithm OID
                    return Ok(Self::detect_key_type_from_algorithm(data));
                }
            }
        }

        // Try SEC1 EC private key
        // EC private key starts with: SEQUENCE { version INTEGER (1), privateKey OCTET STRING }
        if let Ok(_ec_key) = sec1::EcPrivateKey::from_der(data) {
            return Ok(KeyType::Ec);
        }

        // Default to unknown if we can't determine
        Ok(KeyType::Unknown)
    }

    /// Detect key type from algorithm OID in PKCS#8 structure.
    fn detect_key_type_from_algorithm(data: &[u8]) -> KeyType {
        // This is a simplified OID detection
        // RSA OID: 1.2.840.113549.1.1.1 (rsaEncryption)
        // EC OID: 1.2.840.10045.2.1 (ecPublicKey)
        // DSA OID: 1.2.840.10040.4.1

        // Look for OID bytes in the data
        // OID encoding: 0x06 (OID tag) followed by length and value
        let mut i = 0;
        while i < data.len().saturating_sub(10) {
            if data[i] == 0x06 {
                // Found OID tag, check the value
                let len = data[i + 1] as usize;
                if i + 2 + len <= data.len() {
                    let oid_bytes = &data[i + 2..i + 2 + len];
                    if Self::oid_starts_with(oid_bytes, &[42, 134, 72, 134, 247, 13, 1, 1]) {
                        // 1.2.840.113549.1.1.* - RSA
                        return KeyType::Rsa;
                    } else if Self::oid_starts_with(oid_bytes, &[42, 134, 72, 52]) {
                        // 1.2.840.10045.* - EC
                        return KeyType::Ec;
                    } else if oid_bytes.len() > 4
                        && oid_bytes[0] == 42
                        && oid_bytes[1] == 134
                        && oid_bytes[2] == 72
                        && oid_bytes[3] == 52
                    {
                        // Another EC OID variant
                        return KeyType::Ec;
                    }
                }
            }
            i += 1;
        }

        KeyType::Unknown
    }

    /// Check if OID bytes start with the given prefix.
    fn oid_starts_with(oid_bytes: &[u8], prefix: &[u8]) -> bool {
        if oid_bytes.len() < prefix.len() {
            return false;
        }
        oid_bytes[..prefix.len()] == *prefix
    }

    /// Get algorithm OID string for key type.
    fn get_algorithm_oid(key_type: &KeyType) -> String {
        match key_type {
            KeyType::Rsa => "1.2.840.113549.1.1.1".to_string(),
            KeyType::Ec => "1.2.840.10045.2.1".to_string(),
            KeyType::Dsa => "1.2.840.10040.4.1".to_string(),
            KeyType::Unknown => "unknown".to_string(),
        }
    }

    /// Extract curve name from OID.
    fn extract_curve_name(oid: &str) -> Option<String> {
        // Common EC curve OIDs
        let curves = [
            ("1.2.840.10045.3.1.7", "secp256r1 (P-256)"),
            ("1.3.132.0.34", "secp384r1 (P-384)"),
            ("1.3.132.0.35", "secp521r1 (P-521)"),
            ("1.3.132.0.10", "secp256k1"),
            ("1.2.840.10045.3.1.1", "secp192r1 (P-192)"),
            ("1.3.132.0.33", "secp224r1 (P-224)"),
        ];

        for (curve_oid, name) in &curves {
            if oid.contains(curve_oid) {
                return Some(name.to_string());
            }
        }
        None
    }

    /// Extract DER data from PEM.
    fn extract_der_from_pem(pem_data: &[u8]) -> Result<Vec<u8>> {
        use crate::export::pem_to_der;
        pem_to_der(pem_data)
    }

    /// Get a human-readable description of this key.
    pub fn description(&self) -> String {
        let mut desc = format!("{} Private Key", self.key_type);
        if let Some(ref curve) = self.curve_name {
            desc.push_str(&format!(" ({curve})"));
        }
        if let Some(size) = self.key_size {
            desc.push_str(&format!(" (~{} bits)", size));
        }
        if self.is_encrypted {
            desc.push_str(" [ENCRYPTED]");
        }
        desc
    }
}

impl fmt::Display for ParsedPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// Detect if data is a PEM-encoded private key.
pub fn is_pem_private_key(data: &[u8]) -> bool {
    crate::utils::bytes_contains(data, "PRIVATE KEY")
}

/// Detect if data is a PKCS#8 private key.
pub fn is_pkcs8_private_key(data: &[u8]) -> bool {
    crate::utils::bytes_contains_any(
        data,
        &["-----BEGIN PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----"],
    )
}

/// Detect if data is an RSA private key (traditional format).
pub fn is_rsa_private_key(data: &[u8]) -> bool {
    crate::utils::bytes_contains(data, "-----BEGIN RSA PRIVATE KEY-----")
}

/// Detect if data is an EC private key.
pub fn is_ec_private_key(data: &[u8]) -> bool {
    crate::utils::bytes_contains_any(
        data,
        &["-----BEGIN EC PRIVATE KEY-----", "-----BEGIN EC PARAMETERS-----"],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_pem_private_key_with_regular_cert() {
        let cert = include_bytes!("../../assets/baidu.com.pem");
        assert!(!is_pem_private_key(cert));
    }

    #[test]
    fn test_is_pem_private_key_with_pem_key() {
        let pem_key = b"-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA
-----END PRIVATE KEY-----";
        assert!(is_pem_private_key(pem_key));
    }

    #[test]
    fn test_is_pkcs8_private_key() {
        let pkcs8_key = b"-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA
-----END PRIVATE KEY-----";
        assert!(is_pkcs8_private_key(pkcs8_key));
    }

    #[test]
    fn test_is_rsa_private_key() {
        let rsa_key = b"-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs
-----END RSA PRIVATE KEY-----";
        assert!(is_rsa_private_key(rsa_key));
    }

    #[test]
    fn test_is_ec_private_key() {
        let ec_key = b"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINqKfCCOuALZGyXuMmKNLcVXcCBJGIcmFhBqXKPFymPoAoGCCqGSM49
-----END EC PRIVATE KEY-----";
        assert!(is_ec_private_key(ec_key));
    }

    #[test]
    fn test_key_type_display() {
        assert_eq!(format!("{}", KeyType::Rsa), "RSA");
        assert_eq!(format!("{}", KeyType::Ec), "EC");
        assert_eq!(format!("{}", KeyType::Dsa), "DSA");
        assert_eq!(format!("{}", KeyType::Unknown), "Unknown");
    }

    #[test]
    fn test_extract_curve_name() {
        let p256_oid = "1.2.840.10045.3.1.7";
        assert_eq!(
            ParsedPrivateKey::extract_curve_name(p256_oid),
            Some("secp256r1 (P-256)".to_string())
        );

        let p384_oid = "1.3.132.0.34";
        assert_eq!(
            ParsedPrivateKey::extract_curve_name(p384_oid),
            Some("secp384r1 (P-384)".to_string())
        );

        let unknown_oid = "1.2.3.4";
        assert!(ParsedPrivateKey::extract_curve_name(unknown_oid).is_none());
    }

    #[test]
    fn test_parsed_private_key_description() {
        let key = ParsedPrivateKey {
            key_type: KeyType::Rsa,
            algorithm_oid: "1.2.840.113549.1.1.1".to_string(),
            curve_name: None,
            key_size: Some(2048),
            is_encrypted: false,
            format: KeyFormat::Pem,
        };

        assert_eq!(key.description(), "RSA Private Key (~2048 bits)");

        let encrypted_key = ParsedPrivateKey {
            key_type: KeyType::Ec,
            algorithm_oid: "1.2.840.10045.2.1".to_string(),
            curve_name: Some("secp256r1 (P-256)".to_string()),
            key_size: Some(256),
            is_encrypted: true,
            format: KeyFormat::Der,
        };

        assert_eq!(
            encrypted_key.description(),
            "EC Private Key (secp256r1 (P-256)) (~256 bits) [ENCRYPTED]"
        );
    }
}
