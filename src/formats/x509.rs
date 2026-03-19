//! X.509 certificate format parser.
//!
//! This module re-exports the X.509 parsing functionality from the [`cert`](crate::cert)
//! module so callers can use the canonical `formats::x509` path.

// Re-exported as public API for consumers of the library crate.
// Nothing inside this crate uses the `formats::x509::*` path (the binary uses
// `crate::cert` directly), so suppress the "unused" lint that would otherwise fire.
#[allow(unused_imports)]
pub use crate::cert::{
    parse_certificate, parse_certificates, parse_der_certificate, parse_pem_certificate,
    parse_pem_certificates, ParsedCert,
};
