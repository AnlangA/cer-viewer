//! Sensitive data detection and handling utilities.
//!
//! This module provides utilities to detect and handle sensitive data
//! such as private keys, passwords, and other secrets.

use std::sync::LazyLock;

/// Patterns that indicate sensitive data.
static SENSITIVE_PATTERNS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    vec![
        // Private key indicators
        "PRIVATE KEY",
        "PRIVATE KEY-",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        // PKCS#8
        "PKCS#8",
        "PKCS8",
        // Password/passphrase indicators
        "PASSWORD",
        "PASSPHRASE",
        "SECRET",
        // Sensitive field labels
        "Private Key",
        "Private-Key",
        "private_key",
        "private-key",
        // Key material
        "KEY MATERIAL",
        "KEY MATERIAL-",
        // Certificate signing request private part
        "CSR PRIVATE",
    ]
});

/// Check if a label or value potentially contains sensitive data.
///
/// Returns `true` if the input matches any known sensitive pattern.
/// This is a heuristic check - when in doubt, it returns `true` to be safe.
pub fn is_potentially_sensitive(label: &str, value: Option<&str>) -> bool {
    let combined = if let Some(v) = value {
        format!("{} {}", label, v)
    } else {
        label.to_string()
    };

    let combined_upper = combined.to_uppercase();

    // Check against known patterns
    for pattern in SENSITIVE_PATTERNS.iter() {
        if combined_upper.contains(pattern) {
            return true;
        }
    }

    // Check for long hex strings that might be key material
    // (e.g., 32+ bytes of hex without colons)
    if let Some(v) = value {
        let hex_only: String = v.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex_only.len() >= 64 && !v.contains(':') && !v.contains(' ') {
            // Could be raw key material
            return true;
        }
    }

    false
}

/// A warning message to show when copying sensitive data.
pub fn sensitive_copy_warning(data_type: &str) -> String {
    format!(
        "⚠️ WARNING: You are copying {} data. \
        Be careful not to expose this information.",
        data_type
    )
}

/// Classify the type of sensitive data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensitiveDataType {
    /// Private key material
    PrivateKey,
    /// Password or passphrase
    Password,
    /// Secret or token
    Secret,
    /// Unknown sensitive data
    Unknown,
}

impl SensitiveDataType {
    /// Detect the type of sensitive data from label and value.
    pub fn detect(label: &str, value: Option<&str>) -> Option<Self> {
        if !is_potentially_sensitive(label, value) {
            return None;
        }

        let combined = format!("{} {}", label, value.unwrap_or("")).to_uppercase();

        if combined.contains("PRIVATE KEY") || combined.contains("PRIVATE-KEY") {
            Some(Self::PrivateKey)
        } else if combined.contains("PASSWORD") || combined.contains("PASSPHRASE") {
            Some(Self::Password)
        } else if combined.contains("SECRET") {
            Some(Self::Secret)
        } else {
            Some(Self::Unknown)
        }
    }

    /// Get a human-readable description for this data type.
    pub fn description(&self) -> &str {
        match self {
            Self::PrivateKey => "private key",
            Self::Password => "password",
            Self::Secret => "secret",
            Self::Unknown => "sensitive",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_private_key() {
        assert!(is_potentially_sensitive("PRIVATE KEY", None));
        assert!(is_potentially_sensitive(
            "RSA PRIVATE KEY",
            Some("some data")
        ));
        assert!(is_potentially_sensitive("Private Key", Some("content")));
        assert!(is_potentially_sensitive(
            "-----BEGIN PRIVATE KEY-----",
            Some("...")
        ));
    }

    #[test]
    fn test_detect_password() {
        assert!(is_potentially_sensitive("PASSWORD", None));
        assert!(is_potentially_sensitive("Enter Password", Some("********")));
    }

    #[test]
    fn test_detect_secret() {
        assert!(is_potentially_sensitive("SECRET", None));
        assert!(is_potentially_sensitive("API Secret", Some("value")));
    }

    #[test]
    fn test_safe_data_not_sensitive() {
        assert!(!is_potentially_sensitive("Subject", Some("CN=example.com")));
        assert!(!is_potentially_sensitive("Issuer", Some("C=US, O=Test")));
        assert!(!is_potentially_sensitive("Version", Some("V3")));
    }

    #[test]
    fn test_sensitive_data_type_detection() {
        assert_eq!(
            SensitiveDataType::detect("PRIVATE KEY", None),
            Some(SensitiveDataType::PrivateKey)
        );
        assert_eq!(
            SensitiveDataType::detect("PASSWORD", None),
            Some(SensitiveDataType::Password)
        );
        assert_eq!(
            SensitiveDataType::detect("API SECRET", None),
            Some(SensitiveDataType::Secret)
        );
        assert_eq!(SensitiveDataType::detect("Subject", Some("CN=test")), None);
    }

    #[test]
    fn test_sensitive_copy_warning_message() {
        let msg = sensitive_copy_warning("private key");
        assert!(msg.contains("WARNING"));
        assert!(msg.contains("private key"));
    }

    #[test]
    fn test_long_hex_detection() {
        // Short hex is not sensitive
        assert!(!is_potentially_sensitive("Data", Some("1a2b3c4d")));
        // Long hex without separators might be key material
        assert!(is_potentially_sensitive(
            "Key Material",
            Some("1a2b3c4d5e6f78901a2b3c4d5e6f78901a2b3c4d5e6f78901a2b3c4d5e6f7890")
        ));
        // Long hex with colons (like fingerprint) is OK
        assert!(!is_potentially_sensitive(
            "Fingerprint",
            Some("1a:2b:3c:4d:5e:6f:78:90:1a:2b:3c:4d:5e:6f:78:90:1a:2b:3c:4d:5e:6f:78:90:1a:2b:3c:4d:5e:6f:78:90")
        ));
    }
}
