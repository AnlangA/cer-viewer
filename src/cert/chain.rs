//! Certificate chain parsing and visualization.
//!
//! This module provides functionality to build and display certificate chains,
//! showing the hierarchical relationship from leaf certificate through
//! intermediates to the root CA.

#![allow(dead_code)]

use crate::cert::{ParsedCert, ValidityStatus};
use serde::Serialize;
use std::collections::HashMap;

/// A certificate chain with ordered certificates from leaf to root.
#[derive(Debug, Clone, Serialize)]
pub struct CertChain {
    /// Ordered certificates from leaf (index 0) to root (last index).
    pub certificates: Vec<ChainCert>,
    /// Chain validation status.
    pub validation_status: ChainValidationStatus,
}

/// A certificate in the chain with additional metadata.
#[derive(Debug, Clone, Serialize)]
pub struct ChainCert {
    /// The parsed certificate.
    pub cert: ParsedCert,
    /// Position in the chain (0 = leaf, higher = closer to root).
    pub position: ChainPosition,
    /// Whether this certificate can be verified by its issuer in the chain.
    pub signature_valid: bool,
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

            return Self {
                certificates: vec![ChainCert {
                    cert: certs.into_iter().next().unwrap(),
                    position,
                    signature_valid: is_root, // Single cert is valid only if self-signed
                }],
                validation_status: if is_root {
                    ChainValidationStatus::Valid
                } else {
                    ChainValidationStatus::Incomplete { missing_count: 1 }
                },
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
                    signature_valid: true,
                }],
                validation_status: ChainValidationStatus::Valid,
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
        let mut signature_valid = true;
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
                signature_valid = false;
            }

            chain.push(ChainCert {
                cert: cert.clone(),
                position,
                signature_valid: signature_valid && link_valid,
            });

            // Check if we reached a root (issuer is self-signed)
            if Self::is_self_signed(issuer_cert) {
                // Add the root certificate
                chain.push(ChainCert {
                    cert: issuer_cert.clone(),
                    position: ChainPosition::Root,
                    signature_valid: true,
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
                signature_valid: true,
            });
            missing_count = 1;
        }

        // Check if chain ends with a non-self-signed cert (incomplete)
        let last_is_root = chain
            .last()
            .map(|c| matches!(c.position, ChainPosition::Root))
            .unwrap_or(false);

        let validation_status = if !last_is_root {
            ChainValidationStatus::Incomplete {
                missing_count: missing_count.max(1),
            }
        } else if !signature_valid {
            ChainValidationStatus::BrokenLinks
        } else {
            ChainValidationStatus::Valid
        };

        Self {
            certificates: chain,
            validation_status,
        }
    }

    /// Check if a certificate is self-signed (issuer == subject).
    fn is_self_signed(cert: &ParsedCert) -> bool {
        cert.issuer == cert.subject
    }

    /// Get the chain as a tree of fields for UI display.
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
                    if chain_cert.signature_valid {
                        "Yes"
                    } else {
                        "No"
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

fn validity_status_text(status: ValidityStatus) -> &'static str {
    match status {
        ValidityStatus::Valid => "Valid",
        ValidityStatus::Expired => "Expired",
        ValidityStatus::NotYetValid => "Not yet valid",
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
                    signature_valid: true,
                },
                ChainCert {
                    cert: create_test_cert("CN=Root", "CN=Root"),
                    position: ChainPosition::Root,
                    signature_valid: true,
                },
            ],
            validation_status: ChainValidationStatus::Incomplete { missing_count: 0 },
        };

        let tree = chain.to_field_tree();
        assert_eq!(tree.label, "Certificate Chain");
        assert!(tree.children.len() >= 3); // Status + length + certs
    }
}
