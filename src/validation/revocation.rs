//! Certificate revocation checking.

/// Certificate revocation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Certificate is not revoked
    Good,
    /// Certificate is revoked
    Revoked,
    /// Revocation status is unknown
    Unknown,
    /// Revocation check failed
    Error,
}

impl RevocationStatus {
    /// Returns true if the certificate is definitively not revoked.
    pub fn is_good(self) -> bool {
        matches!(self, Self::Good)
    }

    /// Returns true if the certificate is revoked.
    pub fn is_revoked(self) -> bool {
        matches!(self, Self::Revoked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revocation_status() {
        assert!(RevocationStatus::Good.is_good());
        assert!(!RevocationStatus::Good.is_revoked());

        assert!(RevocationStatus::Revoked.is_revoked());
        assert!(!RevocationStatus::Revoked.is_good());

        assert!(!RevocationStatus::Unknown.is_good());
        assert!(!RevocationStatus::Unknown.is_revoked());
    }
}
