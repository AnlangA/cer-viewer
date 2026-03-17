//! Certificate chain validation.

#![allow(dead_code)]

use crate::cert::Result;

/// Certificate chain validator.
pub struct ChainValidator {
    // TODO: Implement chain validation
    /// Trusted root certificates
    trusted_roots: Vec<Vec<u8>>,
}

impl ChainValidator {
    /// Create a new validator with system trust roots.
    pub fn with_system_trust() -> Self {
        Self {
            trusted_roots: Vec::new(),
        }
    }

    /// Create a new validator with custom trust roots.
    pub fn with_trusted_roots(roots: Vec<Vec<u8>>) -> Self {
        Self {
            trusted_roots: roots,
        }
    }

    /// Validate a certificate chain.
    pub fn validate(&self, _chain: &[Vec<u8>]) -> Result<ValidationResult> {
        // TODO: Implement full chain validation
        Ok(ValidationResult::Valid)
    }
}

/// Result of certificate chain validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Chain is valid
    Valid,
    /// Chain is invalid
    Invalid(String),
    /// Validation could not be completed
    Unknown(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validator_creation() {
        let validator = ChainValidator::with_system_trust();
        assert!(validator.trusted_roots.is_empty());
    }

    #[test]
    fn test_validate_empty_chain() {
        let validator = ChainValidator::with_system_trust();
        let result = validator.validate(&[]);
        assert!(matches!(result, Ok(ValidationResult::Valid)));
    }
}
