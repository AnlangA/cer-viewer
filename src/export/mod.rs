//! Export and conversion utilities for certificates and keys.

#![allow(dead_code)]

use crate::cert::{CertError, Result};
use base64::prelude::*;

/// Export data as PEM format.
pub fn to_pem(label: &str, data: &[u8]) -> String {
    let b64 = BASE64_STANDARD.encode(data);
    let mut pem = String::with_capacity(b64.len() + 64);

    pem.push_str("-----BEGIN ");
    pem.push_str(label);
    pem.push_str("-----\n");

    // Split base64 into 64-character lines
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        pem.push('\n');
    }

    pem.push_str("-----END ");
    pem.push_str(label);
    pem.push_str("-----\n");

    pem
}

/// Export data as DER format (just returns the bytes).
pub fn to_der(data: &[u8]) -> Vec<u8> {
    data.to_vec()
}

/// Convert PEM to DER (extract base64 content).
pub fn pem_to_der(pem_data: &[u8]) -> Result<Vec<u8>> {
    let content =
        std::str::from_utf8(pem_data).map_err(|e| CertError::pem(format!("Invalid UTF-8: {e}")))?;

    // Find the base64 content between PEM headers
    let mut in_data = false;
    let mut base64_content = String::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN") {
            in_data = true;
            continue;
        }
        if trimmed.starts_with("-----END") {
            break;
        }
        if in_data {
            base64_content.push_str(trimmed);
        }
    }

    if base64_content.is_empty() {
        return Err(CertError::pem("No PEM content found"));
    }

    BASE64_STANDARD
        .decode(&base64_content)
        .map_err(|e| CertError::pem(format!("Base64 decode error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_pem() {
        let data = b"test data";
        let pem = to_pem("CERTIFICATE", data);
        assert!(pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn test_to_pem_with_line_breaks() {
        // Create data that results in >64 char base64
        let data = vec![0u8; 100];
        let pem = to_pem("CERTIFICATE", &data);

        // Check that lines are broken at 64 characters
        let lines: Vec<&str> = pem.lines().collect();
        let data_lines: Vec<&str> = lines
            .iter()
            .filter(|l| !l.starts_with("-----"))
            .copied()
            .collect();

        // All data lines should be 64 chars or less
        for line in &data_lines {
            assert!(line.len() <= 64, "Line too long: {}", line.len());
        }
    }

    #[test]
    fn test_pem_to_der() {
        // Use the actual test certificate from assets
        const TEST_PEM: &[u8] = include_bytes!("../../assets/baidu.com.pem");
        let der = pem_to_der(TEST_PEM).unwrap();
        assert!(!der.is_empty());
        // The actual certificate should parse correctly
        assert!(der.len() > 500); // Real certificates are larger
    }
}
