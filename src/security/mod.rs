//! Security utilities for protecting sensitive data.
//!
//! This module provides utilities for handling sensitive information like
//! private keys and passwords using zeroize and secrecy.

pub mod protected;
pub mod sensitive;

pub use protected::ProtectedString;
pub use sensitive::{is_potentially_sensitive, sensitive_copy_warning, SensitiveDataType};
