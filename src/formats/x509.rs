//! X.509 certificate format parser.
//!
//! This module re-exports the X.509 parsing functionality from the cert module.

// Re-export the main certificate parsing functions
pub use crate::cert::{
    parse_certificate, parse_certificates, parse_der_certificate, parse_pem_certificate,
    parse_pem_certificates, ParsedCert,
};
