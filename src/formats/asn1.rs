//! ASN.1 structure viewer.
//!
//! This module provides raw ASN.1 DER structure visualization.

use crate::cert::CertField;
use crate::utils::format_hex_block;

/// View ASN.1 DER structure as a tree of fields.
pub fn view_asn1_structure(data: &[u8]) -> CertField {
    let mut children = Vec::new();

    // Basic DER structure parsing
    if data.is_empty() {
        return CertField::leaf("ASN.1", "Empty data");
    }

    // Check for DER SEQUENCE tag
    if data[0] == 0x30 {
        children.push(CertField::leaf("Tag", "SEQUENCE (0x30)"));

        // Parse length
        if data.len() > 1 {
            let length_byte = data[1];
            if length_byte & 0x80 == 0 {
                // Short form length
                children.push(CertField::leaf("Length", format!("{} bytes", length_byte)));
            } else {
                // Long form length
                let num_bytes = (length_byte & 0x7f) as usize;
                children.push(CertField::leaf("Length", format!("Long form ({} bytes)", num_bytes)));
            }
        }

        // Show first few bytes
        let preview_len = data.len().min(32);
        let preview = format_hex_block(&hex::encode(&data[..preview_len]));
        children.push(CertField::leaf("Preview", preview));
    } else {
        children.push(CertField::leaf("Tag", format!("0x{:02X}", data[0])));
        children.push(CertField::leaf("Note", "Not a standard ASN.1 SEQUENCE tag"));
    }

    children.push(CertField::leaf("Total Size", format!("{} bytes", data.len())));

    CertField::container("ASN.1 Structure", children)
}

/// Try to parse an OID from DER-encoded bytes.
pub fn parse_oid(data: &[u8]) -> Option<String> {
    if data.is_empty() || data[0] != 0x06 {
        return None;
    }

    let length = data.len().min(3);
    Some(format!("0x{}", hex::encode(&data[1..length])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_empty_data() {
        let result = view_asn1_structure(&[]);
        assert_eq!(result.label, "ASN.1");
    }

    #[test]
    fn test_view_sequence() {
        // DER SEQUENCE with length 0
        let data = [0x30, 0x00];
        let result = view_asn1_structure(&data);
        assert_eq!(result.label, "ASN.1 Structure");
        assert!(result.children.iter().any(|c| c.label == "Tag"));
    }

    #[test]
    fn test_parse_oid() {
        // Common OID: 1.2.840.113549 (rsaEncryption)
        let oid_bytes = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
        let result = parse_oid(&oid_bytes);
        assert!(result.is_some());
    }
}
