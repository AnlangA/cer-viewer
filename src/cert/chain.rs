//! Certificate chain parsing and visualization.
//!
//! This module provides functionality to build and display certificate chains,
//! showing the hierarchical relationship from leaf certificate through
//! intermediates to the root CA.

use crate::cert::{ParsedCert, ValidityStatus};
use serde::Serialize;
use std::collections::HashMap;
#[cfg(feature = "network")]
use std::collections::HashSet;
#[cfg(feature = "network")]
use tracing::{info, warn};
#[cfg(feature = "network")]
use x509_parser::prelude::*;

/// A certificate chain with ordered certificates from leaf to root.
#[derive(Debug, Clone, Serialize)]
pub struct CertChain {
    /// Ordered certificates from leaf (index 0) to root (last index).
    pub certificates: Vec<ChainCert>,
    /// Chain validation status.
    pub validation_status: ChainValidationStatus,
    /// Human-readable error if chain completion failed (network feature).
    #[cfg(feature = "network")]
    pub completion_error: Option<String>,
}

/// Signature verification status for a certificate in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SignatureStatus {
    /// Signature was verified successfully against the issuer.
    Valid,
    /// Signature verification failed (issuer present but signature doesn't match).
    Invalid,
    /// Signature cannot be verified (issuer is missing from the chain).
    Unknown,
}

/// A certificate in the chain with additional metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ChainCert {
    /// The parsed certificate.
    pub cert: ParsedCert,
    /// Position in the chain (0 = leaf, higher = closer to root).
    pub position: ChainPosition,
    /// Whether this certificate's signature can be verified by its issuer.
    pub signature_status: SignatureStatus,
}

/// Position of a certificate in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ChainPosition {
    /// Leaf certificate (end-entity).
    Leaf,
    /// Intermediate CA certificate.
    Intermediate { depth: usize },
    /// Root CA certificate (self-signed).
    Root,
}

/// Chain validation status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ChainValidationStatus {
    /// Chain is complete and valid.
    Valid,
    /// Chain is incomplete (missing intermediate/root certificates).
    Incomplete { missing_count: usize },
    /// Chain has broken links (issuer-subject mismatch).
    BrokenLinks,
    /// Empty chain.
    Empty,
}

impl CertChain {
    /// Build a certificate chain from a list of certificates.
    ///
    /// This function attempts to order certificates by following issuer
    /// relationships, starting from leaf certificates that are not issuers
    /// of any other certificate, up to self-signed root certificates.
    pub fn build(certs: Vec<ParsedCert>) -> Self {
        if certs.is_empty() {
            return Self {
                certificates: Vec::new(),
                validation_status: ChainValidationStatus::Empty,
                #[cfg(feature = "network")]
                completion_error: None,
            };
        }

        if certs.len() == 1 {
            let cert = &certs[0];
            let is_root = Self::is_self_signed(cert);
            let position = if is_root {
                ChainPosition::Root
            } else {
                ChainPosition::Leaf
            };
            let signature_status = if is_root {
                SignatureStatus::Valid
            } else {
                SignatureStatus::Unknown // Can't verify without issuer
            };

            return Self {
                certificates: vec![ChainCert {
                    cert: certs.into_iter().next().unwrap(),
                    position,
                    signature_status,
                }],
                validation_status: if is_root {
                    ChainValidationStatus::Valid
                } else {
                    ChainValidationStatus::Incomplete { missing_count: 1 }
                },
                #[cfg(feature = "network")]
                completion_error: None,
            };
        }

        // Build a map of subject -> certificate for quick lookup
        let mut subject_map: HashMap<String, usize> = HashMap::new();
        for (i, cert) in certs.iter().enumerate() {
            subject_map.insert(cert.subject.clone(), i);
        }

        // Track which certs are issuers (have their subject as someone's issuer)
        let mut is_issuer = vec![false; certs.len()];
        for (i, cert) in certs.iter().enumerate() {
            if let Some(&issuer_idx) = subject_map.get(&cert.issuer) {
                if issuer_idx != i {
                    is_issuer[issuer_idx] = true;
                }
            }
        }

        // Find leaf certificates (not issuers of any other cert)
        let mut leaf_indices: Vec<usize> = (0..certs.len()).filter(|&i| !is_issuer[i]).collect();

        // If no leaf found (circular or all self-signed), pick the one with non-self issuer
        if leaf_indices.is_empty() {
            for (i, cert) in certs.iter().enumerate() {
                if !Self::is_self_signed(cert) {
                    leaf_indices.push(i);
                }
            }
        }

        // Build chain from first leaf found
        if let Some(&leaf_idx) = leaf_indices.first() {
            Self::build_chain_from_leaf(&certs, &subject_map, leaf_idx)
        } else {
            // All are self-signed, pick first as root
            Self {
                certificates: vec![ChainCert {
                    cert: certs.into_iter().next().unwrap(),
                    position: ChainPosition::Root,
                    signature_status: SignatureStatus::Valid,
                }],
                validation_status: ChainValidationStatus::Valid,
                #[cfg(feature = "network")]
                completion_error: None,
            }
        }
    }

    /// Build chain starting from a specific leaf certificate.
    fn build_chain_from_leaf(
        certs: &[ParsedCert],
        subject_map: &HashMap<String, usize>,
        start_idx: usize,
    ) -> Self {
        let mut chain = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut current_idx = start_idx;
        let mut depth = 0;
        let mut has_broken_link = false;
        let mut missing_count = 0;

        while let Some(&issuer_idx) = subject_map.get(&certs[current_idx].issuer) {
            if visited.contains(&issuer_idx) {
                // Circular reference - stop
                break;
            }
            visited.insert(issuer_idx);

            let cert = &certs[current_idx];
            let issuer_cert = &certs[issuer_idx];

            // Determine position based on current certificate
            let position = if depth == 0 {
                ChainPosition::Leaf
            } else if Self::is_self_signed(cert) {
                ChainPosition::Root
            } else {
                ChainPosition::Intermediate { depth }
            };

            // Verify issuer-subject link
            let link_valid = cert.issuer == issuer_cert.subject;
            if !link_valid {
                has_broken_link = true;
            }

            let sig_status = if link_valid {
                SignatureStatus::Valid
            } else {
                SignatureStatus::Invalid
            };

            chain.push(ChainCert {
                cert: cert.clone(),
                position,
                signature_status: sig_status,
            });

            // Check if we reached a root (issuer is self-signed)
            if Self::is_self_signed(issuer_cert) {
                // Add the root certificate
                chain.push(ChainCert {
                    cert: issuer_cert.clone(),
                    position: ChainPosition::Root,
                    signature_status: SignatureStatus::Valid,
                });
                break;
            }

            // Move to issuer
            current_idx = issuer_idx;
            depth += 1;
        }

        // If we didn't add the leaf yet (no issuer found in chain)
        if chain.is_empty() {
            chain.push(ChainCert {
                cert: certs[start_idx].clone(),
                position: ChainPosition::Leaf,
                signature_status: SignatureStatus::Unknown,
            });
            missing_count = 1;
        }

        // Check if chain ends with a non-self-signed cert (incomplete)
        let last_is_root = chain
            .last()
            .map(|c| matches!(c.position, ChainPosition::Root))
            .unwrap_or(false);

        // Mark the last cert as Unknown if chain is incomplete
        if !last_is_root {
            missing_count = missing_count.max(1);
            // The last cert's issuer is missing — its signature status should be Unknown
            if let Some(last) = chain.last_mut() {
                if last.signature_status == SignatureStatus::Valid {
                    last.signature_status = SignatureStatus::Unknown;
                }
            }
        }

        let validation_status = if !last_is_root {
            ChainValidationStatus::Incomplete { missing_count }
        } else if has_broken_link {
            ChainValidationStatus::BrokenLinks
        } else {
            ChainValidationStatus::Valid
        };

        Self {
            certificates: chain,
            validation_status,
            #[cfg(feature = "network")]
            completion_error: None,
        }
    }

    /// Check if a certificate is self-signed (issuer == subject).
    fn is_self_signed(cert: &ParsedCert) -> bool {
        cert.issuer == cert.subject
    }

    /// Extract CA Issuers URL from the AIA extension of a certificate.
    #[cfg_attr(not(feature = "network"), allow(dead_code))]
    pub fn extract_ca_issuers_url(cert: &ParsedCert) -> Option<String> {
        crate::cert::extract_urls_from_extension(cert, |label| {
            label.contains("CA Issuers")
                || label.contains("certificateAuthority")
                || label.contains("caIssuers")
        })
        .into_iter()
        .next()
    }

    /// Complete the chain by downloading missing issuer certificates from AIA URLs.
    ///
    /// Follows the chain from the last certificate upward, downloading each missing
    /// issuer until a root (self-signed) certificate is reached or no AIA URL is available.
    /// After completion, performs cryptographic signature verification on each link.
    #[cfg(feature = "network")]
    pub fn complete_chain(mut self) -> Self {
        let max_depth = 10;
        let mut depth = 0;
        let mut seen: HashSet<Vec<u8>> = self
            .certificates
            .iter()
            .map(|cc| cc.cert.raw_der.clone())
            .collect();

        while depth < max_depth {
            let last = match self.certificates.last() {
                Some(cc) => cc,
                None => break,
            };

            if Self::is_self_signed(&last.cert) {
                break;
            }

            let url = match Self::extract_ca_issuers_url(&last.cert) {
                Some(u) => u,
                None => {
                    let msg = format!("No AIA CA Issuers URL for {}", last.cert.display_name);
                    info!("{}", msg);
                    self.completion_error = Some(msg);
                    break;
                }
            };

            match download_certificate(&url) {
                Ok(parsed) => {
                    if seen.contains(&parsed.raw_der) {
                        info!("Duplicate certificate from {}, stopping", url);
                        break;
                    }
                    seen.insert(parsed.raw_der.clone());
                    info!(
                        "Downloaded issuer certificate: {} from {}",
                        parsed.display_name, url
                    );

                    let position = if Self::is_self_signed(&parsed) {
                        ChainPosition::Root
                    } else {
                        ChainPosition::Intermediate {
                            depth: self.certificates.len(),
                        }
                    };

                    self.certificates.push(ChainCert {
                        cert: parsed,
                        position,
                        signature_status: SignatureStatus::Unknown,
                    });

                    if matches!(position, ChainPosition::Root) {
                        break;
                    }
                }
                Err(e) => {
                    let msg = format!("Failed to download from {}: {}", url, e);
                    warn!("{}", msg);
                    self.completion_error = Some(msg);
                    break;
                }
            }

            depth += 1;
        }

        // Run crypto verification now that chain is as complete as possible
        Self::verify_signatures(&mut self);

        // Update validation status
        self.validation_status = self.compute_validation_status();
        self
    }

    /// Perform cryptographic signature verification on each link in the chain.
    ///
    /// For each non-root certificate, re-parses it and its issuer's DER data
    /// and calls `verify_signature()` with the issuer's public key.
    #[cfg(feature = "network")]
    fn verify_signatures(chain: &mut Self) {
        for i in 0..chain.certificates.len() {
            let is_root = matches!(chain.certificates[i].position, ChainPosition::Root);
            if is_root {
                chain.certificates[i].signature_status = SignatureStatus::Valid;
                continue;
            }

            let issuer = match chain.certificates.get(i + 1) {
                Some(issuer_cc) => issuer_cc,
                None => {
                    chain.certificates[i].signature_status = SignatureStatus::Unknown;
                    continue;
                }
            };

            // Re-parse both child and issuer DER to get X509Certificate objects
            let child_parsed = match parse_x509_certificate(&chain.certificates[i].cert.raw_der) {
                Ok((_, cert)) => cert,
                Err(_) => continue,
            };

            let issuer_parsed = match parse_x509_certificate(&issuer.cert.raw_der) {
                Ok((_, cert)) => cert,
                Err(_) => {
                    chain.certificates[i].signature_status = SignatureStatus::Unknown;
                    continue;
                }
            };

            match child_parsed.verify_signature(Some(issuer_parsed.public_key())) {
                Ok(()) => {
                    chain.certificates[i].signature_status = SignatureStatus::Valid;
                }
                Err(_) => {
                    chain.certificates[i].signature_status = SignatureStatus::Invalid;
                }
            }
        }
    }

    /// Recompute validation status from the current chain state.
    #[cfg(feature = "network")]
    fn compute_validation_status(&self) -> ChainValidationStatus {
        if self.certificates.is_empty() {
            return ChainValidationStatus::Empty;
        }

        let last_is_root = self
            .certificates
            .last()
            .map(|c| matches!(c.position, ChainPosition::Root))
            .unwrap_or(false);

        let has_invalid = self
            .certificates
            .iter()
            .any(|cc| cc.signature_status == SignatureStatus::Invalid);

        if !last_is_root {
            ChainValidationStatus::Incomplete { missing_count: 1 }
        } else if has_invalid {
            ChainValidationStatus::BrokenLinks
        } else {
            ChainValidationStatus::Valid
        }
    }

    /// Return the list of newly downloaded certificates (not in the original set).
    /// Used by the UI to merge downloaded certs into the app's cert list.
    #[cfg(feature = "network")]
    pub fn downloaded_certs(&self, original_ids: &HashSet<crate::cert::CertId>) -> Vec<ParsedCert> {
        self.certificates
            .iter()
            .filter(|cc| !original_ids.contains(&cc.cert.id))
            .map(|cc| cc.cert.clone())
            .collect()
    }

    /// Get the chain as a tree of fields for UI display.
    #[allow(dead_code)] // Used in tests and reserved for future UI features
    pub fn to_field_tree(&self) -> crate::cert::CertField {
        let mut children = Vec::new();

        // Add chain status
        let status_text = match self.validation_status {
            ChainValidationStatus::Valid => "✓ Valid chain",
            ChainValidationStatus::Incomplete { missing_count } => {
                &format!("⚠ Incomplete chain ({} missing cert(s))", missing_count)
            }
            ChainValidationStatus::BrokenLinks => "✗ Broken links in chain",
            ChainValidationStatus::Empty => "Empty chain",
        };
        children.push(crate::cert::CertField::leaf("Chain Status", status_text));

        // Add chain length
        children.push(crate::cert::CertField::leaf(
            "Chain Length",
            format!("{} certificate(s)", self.certificates.len()),
        ));

        // Add completion error if present
        #[cfg(feature = "network")]
        if let Some(ref err) = self.completion_error {
            children.push(crate::cert::CertField::leaf("Completion Error", err));
        }

        // Add each certificate in the chain
        for (i, chain_cert) in self.certificates.iter().enumerate() {
            let position_label = match chain_cert.position {
                ChainPosition::Leaf => "Leaf",
                ChainPosition::Intermediate { depth } => &format!("Intermediate (depth {})", depth),
                ChainPosition::Root => "Root CA",
            };

            let cert_children = vec![
                crate::cert::CertField::leaf("Position", position_label),
                crate::cert::CertField::leaf("Subject", &chain_cert.cert.subject),
                crate::cert::CertField::leaf("Issuer", &chain_cert.cert.issuer),
                crate::cert::CertField::leaf(
                    "Valid",
                    match chain_cert.signature_status {
                        SignatureStatus::Valid => "Yes",
                        SignatureStatus::Invalid => "No",
                        SignatureStatus::Unknown => "Unknown (issuer missing)",
                    },
                ),
                crate::cert::CertField::leaf(
                    "Validity",
                    validity_status_text(chain_cert.cert.validity_status),
                ),
            ];

            children.push(crate::cert::CertField::container(
                format!("Certificate {}: {}", i + 1, chain_cert.cert.display_name),
                cert_children,
            ));
        }

        crate::cert::CertField::container("Certificate Chain", children)
    }
}

#[allow(dead_code)] // Used by to_field_tree
fn validity_status_text(status: ValidityStatus) -> &'static str {
    match status {
        ValidityStatus::Valid => "Valid",
        ValidityStatus::Expired => "Expired",
        ValidityStatus::NotYetValid => "Not yet valid",
    }
}

/// Download a certificate from a URL (DER or PEM format).
///
/// Requires the `network` feature. Uses a 10-second timeout and 1MB size limit.
#[cfg(feature = "network")]
fn download_certificate(url: &str) -> Result<ParsedCert, String> {
    use std::io::Read;

    let client = reqwest::blocking::ClientBuilder::new()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("cer-viewer")
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let mut response = client
        .get(url)
        .send()
        .map_err(|e| format!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("HTTP error: {}", response.status()));
    }

    let mut data = Vec::new();
    response
        .read_to_end(&mut data)
        .map_err(|e| format!("Failed to read response: {}", e))?;

    const MAX_SIZE: usize = 1024 * 1024; // 1MB
    if data.len() > MAX_SIZE {
        return Err(format!("Certificate too large: {} bytes", data.len()));
    }

    // Try to detect format
    if data.starts_with(b"-----BEGIN") {
        crate::cert::parse_pem_certificate(&data).map_err(|e| format!("{}", e))
    } else {
        crate::cert::parse_der_certificate(&data).map_err(|e| format!("{}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::CertId;

    fn create_test_cert(subject: &str, issuer: &str) -> ParsedCert {
        ParsedCert {
            id: CertId(subject.to_string()),
            display_name: subject.to_string(),
            serial_number: "00:11:22:33".to_string(),
            sha256_fingerprint: "AA:BB:CC:DD".to_string(),
            sha1_fingerprint: "11:22:33:44".to_string(),
            validity_status: ValidityStatus::Valid,
            not_before: "2024-01-01 00:00:00 UTC".to_string(),
            not_after: "2025-01-01 00:00:00 UTC".to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            fields: Vec::new(),
            raw_der: Vec::new(),
        }
    }

    #[test]
    fn test_empty_chain() {
        let chain = CertChain::build(Vec::new());
        assert_eq!(chain.certificates.len(), 0);
        assert_eq!(chain.validation_status, ChainValidationStatus::Empty);
    }

    #[test]
    fn test_single_self_signed_cert() {
        let cert = create_test_cert("CN=Root CA", "CN=Root CA");
        let chain = CertChain::build(vec![cert]);

        assert_eq!(chain.certificates.len(), 1);
        assert_eq!(chain.certificates[0].position, ChainPosition::Root);
        assert_eq!(chain.validation_status, ChainValidationStatus::Valid);
    }

    #[test]
    fn test_single_non_self_signed_cert() {
        let cert = create_test_cert("CN=Leaf", "CN=Intermediate CA");
        let chain = CertChain::build(vec![cert]);

        assert_eq!(chain.certificates.len(), 1);
        assert_eq!(chain.certificates[0].position, ChainPosition::Leaf);
        assert_eq!(
            chain.validation_status,
            ChainValidationStatus::Incomplete { missing_count: 1 }
        );
    }

    #[test]
    fn test_simple_chain_of_three() {
        let leaf = create_test_cert("CN=example.com", "CN=Intermediate CA");
        let intermediate = create_test_cert("CN=Intermediate CA", "CN=Root CA");
        let root = create_test_cert("CN=Root CA", "CN=Root CA");

        let chain = CertChain::build(vec![root, intermediate, leaf]);

        assert_eq!(chain.certificates.len(), 3);
        assert_eq!(chain.certificates[0].position, ChainPosition::Leaf);
        assert_eq!(
            chain.certificates[1].position,
            ChainPosition::Intermediate { depth: 1 }
        );
        assert_eq!(chain.certificates[2].position, ChainPosition::Root);
        assert_eq!(chain.validation_status, ChainValidationStatus::Valid);
    }

    #[test]
    fn test_is_self_signed() {
        let self_signed = create_test_cert("CN=Root", "CN=Root");
        assert!(CertChain::is_self_signed(&self_signed));

        let not_self_signed = create_test_cert("CN=Leaf", "CN=Root");
        assert!(!CertChain::is_self_signed(&not_self_signed));
    }

    #[test]
    fn test_chain_position_display() {
        let chain = CertChain {
            certificates: vec![
                ChainCert {
                    cert: create_test_cert("CN=Leaf", "CN=Root"),
                    position: ChainPosition::Leaf,
                    signature_status: SignatureStatus::Valid,
                },
                ChainCert {
                    cert: create_test_cert("CN=Root", "CN=Root"),
                    position: ChainPosition::Root,
                    signature_status: SignatureStatus::Valid,
                },
            ],
            validation_status: ChainValidationStatus::Incomplete { missing_count: 0 },
            #[cfg(feature = "network")]
            completion_error: None,
        };

        let tree = chain.to_field_tree();
        assert_eq!(tree.label, "Certificate Chain");
        assert!(tree.children.len() >= 3); // Status + length + certs
    }

    #[test]
    fn test_extract_ca_issuers_url_from_baidu() {
        let data = include_bytes!("../../assets/baidu.com.pem");
        let cert = crate::cert::parse_pem_certificate(data).unwrap();
        let url = CertChain::extract_ca_issuers_url(&cert);
        assert!(url.is_some(), "Expected CA Issuers URL in baidu.com.pem");
        let url = url.unwrap();
        assert!(url.starts_with("http://") || url.starts_with("https://"));
        assert!(
            !url.contains("URI:"),
            "URL should not contain 'URI:' prefix"
        );
    }

    #[test]
    #[cfg(feature = "network")]
    fn test_complete_chain_sets_error_on_no_aia() {
        let cert = create_test_cert("CN=Leaf", "CN=Unknown CA");
        let chain = CertChain::build(vec![cert]).complete_chain();
        assert!(chain.completion_error.is_some());
        assert!(
            chain.completion_error.as_ref().unwrap().contains("No AIA"),
            "Expected 'No AIA' in error, got: {:?}",
            chain.completion_error
        );
    }
}
