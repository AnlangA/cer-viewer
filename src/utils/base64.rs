//! Base64 encoding/decoding utilities.

#![allow(dead_code)]

use crate::cert::Result;
use base64::prelude::*;

/// Encode bytes as hex string with colons (AA:BB:CC format).
pub fn format_bytes_hex_colon(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let mut result = String::with_capacity(bytes.len() * 3 - 1);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            result.push(':');
        }
        push_hex_byte(&mut result, *b);
    }
    result
}

/// Encode bytes as continuous hex string.
pub fn format_bytes_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Format a hex string with colons (e.g., "AA:BB:CC").
pub fn format_hex_block(hex_str: &str) -> String {
    hex_str
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap_or("??"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Push a single byte as uppercase hex to a string.
fn push_hex_byte(s: &mut String, b: u8) {
    const HEX_CHARS: &[u8; 16] = b"0123456789ABCDEF";
    s.push(HEX_CHARS[(b >> 4) as usize] as char);
    s.push(HEX_CHARS[(b & 0x0F) as usize] as char);
}

/// Decode base64 data.
pub fn decode_base64(data: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(data)
        .map_err(|e| crate::cert::CertError::pem(format!("Base64 decode error: {e}")))
}

/// Encode data as base64.
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
