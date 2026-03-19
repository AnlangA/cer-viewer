//! Verification report data types.
//!
//! Serializable structs representing the output of certificate verification,
//! suitable for both human-readable text display and JSON output.

use serde::Serialize;

/// Overall verification status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OverallStatus {
    /// All checks passed.
    Ok,
    /// At least one critical check failed.
    Failed,
    /// All checks passed but with warnings (e.g., self-signed without trust store).
    Warning,
}

/// Full verification report for one or more certificates.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    /// Overall result across all certificates and chain.
    pub overall_status: OverallStatus,
    /// Per-certificate verification details.
    pub certificates: Vec<CertVerification>,
    /// Chain-level verification details (empty if single cert).
    pub chain: Option<ChainVerification>,
}

/// Per-certificate verification result.
#[derive(Debug, Clone, Serialize)]
pub struct CertVerification {
    /// Display name (typically CN).
    pub name: String,
    /// Subject DN.
    pub subject: String,
    /// Issuer DN.
    pub issuer: String,
    /// Time validity check.
    pub time_validity: TimeValidityResult,
    /// Signature verification against issuer.
    pub signature: SignatureResult,
    /// Trust status.
    pub trust: TrustResult,
    /// Whether the certificate is self-signed.
    pub self_signed: bool,
    /// Key Usage extension values (empty if not present).
    pub key_usage: Vec<String>,
    /// Extended Key Usage extension values (empty if not present).
    pub extended_key_usage: Vec<String>,
    /// Subject Alternative Name entries.
    pub san_entries: Vec<SanEntry>,
}

/// Time validity check result.
#[derive(Debug, Clone, Serialize)]
pub struct TimeValidityResult {
    /// Whether the certificate is within its validity period.
    pub valid: bool,
    /// Human-readable status label.
    pub status: String,
    /// Not Before timestamp.
    pub not_before: String,
    /// Not After timestamp.
    pub not_after: String,
}

/// Signature verification result.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureResult {
    /// Whether the signature was verified.
    pub verified: bool,
    /// Human-readable status label.
    pub status: String,
}

/// Trust status of a certificate.
#[derive(Debug, Clone, Serialize)]
pub struct TrustResult {
    /// Whether the certificate (or chain root) is trusted.
    pub trusted: bool,
    /// Human-readable status label.
    pub status: String,
}

/// A Subject Alternative Name entry.
#[derive(Debug, Clone, Serialize)]
pub struct SanEntry {
    /// The type of SAN (DNS, IP, email, etc.).
    pub san_type: String,
    /// The value.
    pub value: String,
}

/// Chain-level verification result.
#[derive(Debug, Clone, Serialize)]
pub struct ChainVerification {
    /// Whether the chain is structurally valid.
    pub valid: bool,
    /// Human-readable status label.
    pub status: String,
    /// Number of certificates in the chain.
    pub length: usize,
    /// Human-readable structural validation result.
    pub structural_check: String,
    /// Per-link verification info.
    pub links: Vec<ChainLinkInfo>,
}

/// Per-link verification info in a chain.
#[derive(Debug, Clone, Serialize)]
pub struct ChainLinkInfo {
    /// Certificate display name.
    pub name: String,
    /// Position label (Leaf, Intermediate, Root).
    pub position: String,
    /// Signature verification status for this link.
    pub signature_status: String,
    /// Whether this certificate is self-signed.
    pub self_signed: bool,
    /// Whether this certificate is trusted.
    pub trusted: bool,
}
