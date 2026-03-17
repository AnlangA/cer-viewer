//! Error types for the certificate viewer.
//!
//! Provides structured error handling using `thiserror`.

use std::path::PathBuf;

/// Result type alias for certificate viewer operations.
pub type Result<T> = std::result::Result<T, CertError>;

/// Errors that can occur in the certificate viewer.
#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // Some error variants are reserved for future use
pub enum CertError {
    /// Failed to parse PEM-encoded data.
    #[error("PEM parse error: {0}")]
    PemParse(String),

    /// Failed to parse DER-encoded data.
    #[error("DER parse error: {0}")]
    DerParse(String),

    /// Failed to read a file.
    #[error("Failed to read file '{path}': {source}")]
    FileRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to access clipboard.
    #[error("Clipboard error: {0}")]
    Clipboard(String),

    /// Certificate validation failed.
    #[error("Certificate validation failed: {0}")]
    Validation(String),

    /// Unsupported format.
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    /// No certificate data found.
    #[error("No certificate data found")]
    NoCertificate,
}

impl CertError {
    /// Create a PEM parse error with context.
    pub fn pem(msg: impl Into<String>) -> Self {
        Self::PemParse(msg.into())
    }

    /// Create a DER parse error with context.
    pub fn der(msg: impl Into<String>) -> Self {
        Self::DerParse(msg.into())
    }

    /// Create a general parse error.
    pub fn parse(msg: impl Into<String>) -> Self {
        Self::PemParse(msg.into())
    }
}
