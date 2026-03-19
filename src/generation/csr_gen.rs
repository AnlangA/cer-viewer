//! Certificate Signing Request (CSR) generation.

use crate::cert::CertError;
use crate::cert::Result;
use crate::generation::self_signed::{generate_key_pair, KeyType};
use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, SanType};

/// Parameters for generating a CSR.
#[derive(Debug, Clone)]
pub struct CsrParams {
    /// Common Name (CN) for the CSR.
    pub cn: String,
    /// Optional Subject Alternative Names (DNS names or IP addresses).
    pub sans: Vec<String>,
    /// Key type to use (RSA or EC).
    pub key_type: KeyType,
    /// Key size in bits.
    pub key_size: u32,
}

/// Result of generating a CSR.
#[allow(dead_code)]
pub struct GeneratedCsr {
    /// The CSR in PEM format.
    pub pem: String,
    /// The CSR in DER format.
    pub der: Vec<u8>,
    /// The private key in PEM format.
    pub key_pem: String,
    /// The private key in DER format.
    pub key_der: Vec<u8>,
}

/// Generate a Certificate Signing Request with the given parameters.
///
/// Returns a `GeneratedCsr` containing the CSR and private key
/// in PEM and DER formats.
pub fn generate_csr(params: &CsrParams) -> Result<GeneratedCsr> {
    params.key_type.validate_key_size(params.key_size)?;

    let mut cert_params = CertificateParams::default();

    // Set distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &params.cn);
    cert_params.distinguished_name = dn;

    // Set key pair
    let key_pair = generate_key_pair(params.key_type, params.key_size)?;

    // Set SANs
    let mut san_entries = Vec::new();
    for san in &params.sans {
        if let Ok(addr) = san.parse::<std::net::IpAddr>() {
            san_entries.push(SanType::IpAddress(addr));
        } else {
            san_entries.push(SanType::DnsName(san.clone().try_into().map_err(|e| {
                CertError::parse(format!("Invalid DNS name '{}': {e}", san))
            })?));
        }
    }
    cert_params.subject_alt_names = san_entries;

    // Mark as not CA for CSR
    cert_params.is_ca = IsCa::NoCa;

    // Generate the CSR
    let csr = cert_params
        .serialize_request(&key_pair)
        .map_err(|e| CertError::parse(format!("Failed to generate CSR: {e}")))?;

    let pem = csr
        .pem()
        .map_err(|e| CertError::parse(format!("Failed to serialize CSR PEM: {e}")))?;
    let der = csr.der().to_vec();
    let key_pem = key_pair.serialize_pem();
    let key_der = key_pair.serialize_der();

    Ok(GeneratedCsr {
        pem,
        der,
        key_pem,
        key_der,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generation::self_signed::KeyType;

    fn default_params(cn: &str) -> CsrParams {
        CsrParams {
            cn: cn.to_string(),
            sans: Vec::new(),
            key_type: KeyType::Rsa,
            key_size: 2048,
        }
    }

    #[test]
    fn test_generate_csr_basic() {
        let params = default_params("Test CSR");
        let result = generate_csr(&params);
        assert!(result.is_ok(), "CSR generation failed: {:?}", result.err());
        let csr = result.unwrap();
        assert!(!csr.der.is_empty());
        assert!(csr.pem.contains("-----BEGIN CERTIFICATE REQUEST-----"));
        assert!(!csr.key_pem.is_empty());
        assert!(!csr.key_der.is_empty());
    }

    #[test]
    fn test_generate_csr_ec() {
        let params = CsrParams {
            key_type: KeyType::Ec,
            key_size: 256,
            ..default_params("EC CSR Test")
        };
        let result = generate_csr(&params);
        assert!(
            result.is_ok(),
            "EC CSR generation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_generate_csr_with_san() {
        let params = CsrParams {
            sans: vec!["example.com".to_string(), "www.example.com".to_string()],
            ..default_params("SAN CSR Test")
        };
        let result = generate_csr(&params);
        assert!(
            result.is_ok(),
            "SAN CSR generation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_generate_csr_with_ip_san() {
        let params = CsrParams {
            sans: vec!["10.0.0.1".to_string()],
            ..default_params("IP SAN CSR Test")
        };
        let result = generate_csr(&params);
        assert!(
            result.is_ok(),
            "IP SAN CSR generation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_csr_is_parseable() {
        let params = default_params("Parseable CSR");
        let result = generate_csr(&params).unwrap();
        // Verify the DER can be parsed
        let parsed = crate::formats::csr::parse_csr_der(&result.der);
        assert!(parsed.is_ok(), "Generated CSR should be parseable");
        let csr = parsed.unwrap();
        assert!(csr.subject.contains("Parseable CSR"));
    }

    #[test]
    fn test_csr_key_pair_serialization() {
        let params = default_params("KeyPair CSR Test");
        let result = generate_csr(&params).unwrap();
        assert!(result.key_der.len() > 100);
        assert!(result.key_pem.contains("-----BEGIN"));
    }

    #[test]
    fn test_invalid_key_size_returns_error() {
        let params = CsrParams {
            key_size: 1024,
            ..default_params("Invalid Size CSR")
        };
        let result = generate_csr(&params);
        assert!(result.is_err());
    }
}
