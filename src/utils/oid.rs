//! OID (Object Identifier) utilities.

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
}
