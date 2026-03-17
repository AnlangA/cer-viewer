//! Protected string types for sensitive data.
//!
//! Uses secrecy to prevent accidental leakage of sensitive information.

#![allow(dead_code)]

use zeroize::Zeroize;

/// A protected string that cannot be accidentally logged or copied.
///
/// Note: This is a simplified version. For production use, consider using
/// the full secrecy crate with proper secret type wrapping.
#[derive(Clone)]
pub struct ProtectedString(String);

impl ProtectedString {
    /// Create a new protected string.
    pub fn new(s: String) -> Self {
        Self(s)
    }

    /// Expose the inner value (use with caution).
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Check if the string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for ProtectedString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

// Implement Zeroize for extra safety
impl Zeroize for ProtectedString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for ProtectedString {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protected_string() {
        let secret = ProtectedString::new("password123".to_string());
        assert_eq!(secret.expose(), "password123");
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_protected_string_empty() {
        let secret = ProtectedString::new(String::new());
        assert!(secret.is_empty());
    }

    #[test]
    fn test_protected_string_from_string() {
        let s: String = "test".to_string();
        let protected: ProtectedString = s.into();
        assert_eq!(protected.expose(), "test");
    }
}
