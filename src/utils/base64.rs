//! Base64 encoding/decoding utilities.

use crate::cert::Result;
use base64::prelude::*;

/// Encode bytes as hex string with colons (AA:BB:CC format).
pub fn format_bytes_hex_colon(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
    let mut result = String::with_capacity(bytes.len() * 3 - 1);

    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        // Inline hex encoding for better performance
        result.push(HEX_CHARS[(b >> 4) as usize] as char);
        result.push(HEX_CHARS[(b & 0x0F) as usize] as char);
    }
    result
}

/// Encode bytes as continuous hex string.
#[allow(dead_code)] // Public API utility
pub fn format_bytes_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Format a hex string with colons (e.g., "AA:BB:CC").
///
/// This avoids intermediate allocations by pre-calculating the capacity
/// and using direct byte manipulation.
pub fn format_hex_block(hex_str: &str) -> String {
    let bytes = hex_str.as_bytes();
    if bytes.len() < 2 {
        return hex_str.to_string();
    }

    let chunk_count = bytes.len().div_ceil(2);
    let mut result = String::with_capacity(bytes.len() + chunk_count - 1);

    for (i, chunk) in bytes.chunks(2).enumerate() {
        if i > 0 {
            result.push(':');
        }
        // Direct byte push is faster than push_str for small chunks
        result.push(chunk[0] as char);
        if chunk.len() == 2 {
            result.push(chunk[1] as char);
        }
    }
    result
}

/// Decode base64 data.
#[allow(dead_code)] // Public API utility
pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(data)
        .map_err(|e| crate::cert::CertError::pem(format!("Base64 decode error: {e}")))
}

/// Encode data as base64.
#[allow(dead_code)] // Public API utility
pub fn encode_base64(data: &[u8]) -> String {
    BASE64_STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_hex_colon() {
        let bytes = &[0x0E, 0x7F, 0xA9, 0x2B];
        let result = format_bytes_hex_colon(bytes);
        assert_eq!(result, "0E:7F:A9:2B");
    }

    #[test]
    fn test_format_bytes_hex_colon_empty() {
        let bytes: &[u8] = &[];
        let result = format_bytes_hex_colon(bytes);
        assert!(result.is_empty());
    }

    #[test]
    fn test_format_bytes_hex() {
        let bytes = &[0x0E, 0x7F, 0xA9, 0x2B];
        let result = format_bytes_hex(bytes);
        assert_eq!(result, "0e7fa92b");
    }

    #[test]
    fn test_format_hex_block() {
        let result = format_hex_block("aabbccdd");
        assert_eq!(result, "aa:bb:cc:dd");
    }

    #[test]
    fn test_base64_roundtrip() {
        let original = b"Hello, World!";
        let encoded = encode_base64(original);
        let decoded = decode_base64(&encoded).unwrap();
        assert_eq!(original, decoded.as_slice());
    }
}
