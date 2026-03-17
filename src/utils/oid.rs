//! OID (Object Identifier) utilities.

#![allow(dead_code)]

use oid_registry::OidRegistry;
use std::sync::LazyLock;

/// Global OID registry (cached).
pub(crate) static OID_REGISTRY: LazyLock<OidRegistry<'static>> =
    LazyLock::new(|| OidRegistry::default().with_all_crypto().with_x509());

/// Describe an OID using the registry.
pub fn describe_oid(oid: &oid_registry::Oid<'_>) -> String {
    if let Some(entry) = OID_REGISTRY.get(oid) {
        let name = entry.sn();
        if name.is_empty() {
            entry.description().to_string()
        } else {
            name.to_string()
        }
    } else {
        format!("{oid}")
    }
}

/// Check if an OID matches a known pattern.
pub fn oid_matches(oid: &oid_registry::Oid<'_>, pattern: &[u32]) -> bool {
    match oid.iter() {
        Some(iter) => {
            // Collect into a Vec and compare
            let oid_components: Vec<u64> = iter.collect();
            if oid_components.len() != pattern.len() {
                return false;
            }
            oid_components
                .iter()
                .zip(pattern.iter())
                .all(|(a, b)| *a == *b as u64)
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_describe_known_oid() {
        // Test with a well-known OID
        let oid_res = oid_registry::Oid::from(&[2, 5, 4][..]);
        if let Ok(ref oid) = oid_res {
            let desc = describe_oid(oid);
            // OID should be present in the description, either by name or by number
            assert!(!desc.is_empty());
        }
    }

    #[test]
    fn test_oid_matches() {
        let oid_res = oid_registry::Oid::from(&[1, 2, 840, 113549, 1, 1, 1][..]);
        if let Ok(ref oid) = oid_res {
            assert!(oid_matches(oid, &[1, 2, 840, 113549, 1, 1, 1]));
        }

        let oid2_res = oid_registry::Oid::from(&[2, 5, 4][..]);
        if let Ok(ref oid2) = oid2_res {
            assert!(oid_matches(oid2, &[2, 5, 4]));
        }

        if let Ok(ref oid) = oid_res {
            assert!(!oid_matches(oid, &[1, 2, 3]));
        }
    }
}
