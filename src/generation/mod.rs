//! Certificate generation module.
//!
//! Provides functionality for generating self-signed certificates and CSRs
//! using the `rcgen` crate.

pub(crate) mod csr_gen;
pub(crate) mod self_signed;

#[allow(unused_imports)]
pub use csr_gen::{generate_csr, CsrParams};
#[allow(unused_imports)]
pub use self_signed::{generate_self_signed_cert, SelfSignedParams};
