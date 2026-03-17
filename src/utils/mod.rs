//! Utility functions for certificate processing.

pub mod base64;
pub mod oid;
pub mod time;

pub use base64::{format_bytes_hex_colon, format_hex_block};
pub use oid::describe_oid;

/// Check if byte data contains a string pattern, avoiding intermediate String allocation.
///
/// This is more efficient than `String::from_utf8_lossy(data).contains(pattern)`
/// for simple substring checks.
pub fn bytes_contains(data: &[u8], pattern: &str) -> bool {
    let pattern_bytes = pattern.as_bytes();
    // Empty pattern matches anything (matches standard str::contains behavior)
    if pattern_bytes.is_empty() {
        return true;
    }
    // Non-empty pattern can't match empty data
    if data.is_empty() {
        return false;
    }

    // Simple byte-by-byte search
    data.windows(pattern_bytes.len())
        .any(|window| window == pattern_bytes)
}

/// Check if byte data contains any of the given string patterns.
pub fn bytes_contains_any(data: &[u8], patterns: &[&str]) -> bool {
    patterns.iter().any(|p| bytes_contains(data, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes_contains() {
        assert!(bytes_contains(b"Hello World", "World"));
        assert!(bytes_contains(b"Hello World", "Hello"));
        assert!(bytes_contains(b"Hello World", "lo Wo"));
        assert!(!bytes_contains(b"Hello World", "xyz"));
        assert!(!bytes_contains(b"", "test"));
    }

    #[test]
    fn test_bytes_contains_any() {
        assert!(bytes_contains_any(b"Hello World", &["Hello", "Goodbye"]));
        assert!(bytes_contains_any(b"Hello World", &["xyz", "World"]));
        assert!(!bytes_contains_any(b"Hello", &["xyz", "abc"]));
    }

    #[test]
    fn test_bytes_contains_empty() {
        // Empty pattern matches anything (matches standard str::contains behavior)
        assert!(bytes_contains(b"Hello", ""));
        assert!(bytes_contains(b"", ""));
        assert!(!bytes_contains(b"", "test"));
    }
}
