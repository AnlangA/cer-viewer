//! Self-signed certificate generation.

use crate::cert::CertError;
use crate::cert::Result;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, RsaKeySize,
    SanType, SerialNumber,
};
use time::{Duration, OffsetDateTime};

/// Parameters for generating a self-signed certificate.
#[derive(Debug, Clone)]
pub struct SelfSignedParams {
    /// Common Name (CN) for the certificate.
    pub cn: String,
    /// Number of days the certificate should be valid.
    pub validity_days: u32,
    /// Key type to use (RSA or EC).
    pub key_type: KeyType,
    /// Key size in bits (e.g., 2048 for RSA, 256 for EC/P-256).
    pub key_size: u32,
    /// Optional Subject Alternative Names (DNS names or IP addresses).
    pub sans: Vec<String>,
    /// Whether this certificate should be a CA certificate.
    pub is_ca: bool,
}

/// Supported key types for certificate generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    /// RSA key.
    Rsa,
    /// Elliptic curve key.
    Ec,
}

impl KeyType {
    /// Default key size for this key type.
    pub fn default_key_size(&self) -> u32 {
        match self {
            KeyType::Rsa => 2048,
            KeyType::Ec => 256,
        }
    }

    /// Validate the key size for this key type.
    pub fn validate_key_size(&self, key_size: u32) -> Result<()> {
        match self {
            KeyType::Rsa => match key_size {
                2048 | 3072 | 4096 => Ok(()),
                _ => Err(CertError::parse(format!(
                    "Unsupported RSA key size: {}. Supported: 2048, 3072, 4096",
                    key_size
                ))),
            },
            KeyType::Ec => match key_size {
                256 | 384 | 521 => Ok(()),
                _ => Err(CertError::parse(format!(
                    "Unsupported EC key size: {}. Supported: 256 (P-256), 384 (P-384), 521 (P-521)",
                    key_size
                ))),
            },
        }
    }
}

/// Result of generating a self-signed certificate.
#[allow(dead_code)]
pub struct GeneratedCert {
    /// The certificate in DER format.
    pub der: Vec<u8>,
    /// The certificate in PEM format.
    pub pem: String,
    /// The private key in DER format.
    pub key_der: Vec<u8>,
    /// The private key in PEM format.
    pub key_pem: String,
}

/// Generate a self-signed certificate with the given parameters.
///
/// Returns a `GeneratedCert` containing both certificate and private key
/// in PEM and DER formats.
pub fn generate_self_signed_cert(params: &SelfSignedParams) -> Result<GeneratedCert> {
    params.key_type.validate_key_size(params.key_size)?;

    let mut cert_params = CertificateParams::default();

    // Set distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &params.cn);
    cert_params.distinguished_name = dn;

    // Set validity period
    let now = OffsetDateTime::now_utc();
    cert_params.not_before = now;
    cert_params.not_after = now + Duration::days(params.validity_days as i64);

    // Set key pair
    let key_pair = generate_key_pair(params.key_type, params.key_size)?;

    // Set serial number (random)
    cert_params.serial_number = Some(SerialNumber::from_slice(
        &(0..20).map(|_| rand::random::<u8>()).collect::<Vec<u8>>(),
    ));

    // Set CA flag
    if params.is_ca {
        cert_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }

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

    // Generate the self-signed certificate
    let cert = cert_params
        .self_signed(&key_pair)
        .map_err(|e| CertError::parse(format!("Failed to generate certificate: {e}")))?;

    let der = cert.der().to_vec();
    let pem = cert.pem();
    let key_der = key_pair.serialize_der();
    let key_pem = key_pair.serialize_pem();

    Ok(GeneratedCert {
        der,
        pem,
        key_der,
        key_pem,
    })
}

/// Generate a key pair for the specified key type and size.
pub(crate) fn generate_key_pair(key_type: KeyType, key_size: u32) -> Result<KeyPair> {
    match key_type {
        KeyType::Rsa => {
            let rsa_size = match key_size {
                2048 => RsaKeySize::_2048,
                3072 => RsaKeySize::_3072,
                4096 => RsaKeySize::_4096,
                _ => {
                    return Err(CertError::parse(format!(
                        "Unsupported RSA key size: {}",
                        key_size
                    )))
                }
            };
            KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rsa_size)
                .map_err(|e| CertError::parse(format!("Failed to generate RSA key pair: {e}")))
        }
        KeyType::Ec => {
            let alg = match key_size {
                256 => &rcgen::PKCS_ECDSA_P256_SHA256,
                384 => &rcgen::PKCS_ECDSA_P384_SHA384,
                521 => &rcgen::PKCS_ECDSA_P521_SHA256,
                _ => {
                    return Err(CertError::parse(format!(
                        "Unsupported EC key size: {}",
                        key_size
                    )))
                }
            };
            KeyPair::generate_for(alg)
                .map_err(|e| CertError::parse(format!("Failed to generate EC key pair: {e}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_params(cn: &str) -> SelfSignedParams {
        SelfSignedParams {
            cn: cn.to_string(),
            validity_days: 365,
            key_type: KeyType::Rsa,
            key_size: 2048,
            sans: Vec::new(),
            is_ca: false,
        }
    }

    #[test]
    fn test_generate_self_signed_basic() {
        let params = default_params("Test Certificate");
        let result = generate_self_signed_cert(&params);
        assert!(result.is_ok(), "Generation failed: {:?}", result.err());
        let cert = result.unwrap();
        assert!(!cert.der.is_empty());
        assert!(cert.pem.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.pem.contains("-----END CERTIFICATE-----"));
        assert!(!cert.key_pem.is_empty());
        assert!(!cert.key_der.is_empty());
    }

    #[test]
    fn test_generate_self_signed_ec() {
        let params = SelfSignedParams {
            key_type: KeyType::Ec,
            key_size: 256,
            ..default_params("EC Test")
        };
        let result = generate_self_signed_cert(&params);
        assert!(result.is_ok(), "EC generation failed: {:?}", result.err());
    }

    #[test]
    fn test_generate_self_signed_with_san() {
        let params = SelfSignedParams {
            sans: vec![
                "example.com".to_string(),
                "www.example.com".to_string(),
                "192.168.1.1".to_string(),
            ],
            ..default_params("SAN Test")
        };
        let result = generate_self_signed_cert(&params);
        assert!(result.is_ok(), "SAN generation failed: {:?}", result.err());
    }

    #[test]
    fn test_generate_self_signed_ca() {
        let params = SelfSignedParams {
            is_ca: true,
            ..default_params("Test CA")
        };
        let result = generate_self_signed_cert(&params);
        assert!(result.is_ok(), "CA generation failed: {:?}", result.err());
    }

    #[test]
    fn test_generate_self_signed_with_rsa_4096() {
        let params = SelfSignedParams {
            key_size: 4096,
            ..default_params("RSA 4096 Test")
        };
        let result = generate_self_signed_cert(&params);
        assert!(
            result.is_ok(),
            "RSA 4096 generation failed: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_invalid_rsa_key_size() {
        let result = KeyType::Rsa.validate_key_size(1024);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ec_key_size() {
        let result = KeyType::Ec.validate_key_size(512);
        assert!(result.is_err());
    }

    #[test]
    fn test_default_key_sizes() {
        assert_eq!(KeyType::Rsa.default_key_size(), 2048);
        assert_eq!(KeyType::Ec.default_key_size(), 256);
    }

    #[test]
    fn test_generated_cert_is_parseable() {
        let params = default_params("Parseable Cert");
        let result = generate_self_signed_cert(&params).unwrap();
        // Verify the DER can be parsed by x509-parser
        let parsed = crate::cert::parse_der_certificate(&result.der);
        assert!(parsed.is_ok(), "Generated cert should be parseable");
        let cert = parsed.unwrap();
        assert!(cert.subject.contains("Parseable Cert"));
    }

    #[test]
    fn test_key_pair_serialization_roundtrip() {
        let params = default_params("Roundtrip Test");
        let result = generate_self_signed_cert(&params).unwrap();
        // DER and PEM should both be non-empty
        assert!(result.key_der.len() > 100);
        assert!(result.key_pem.contains("-----BEGIN"));
    }
}
