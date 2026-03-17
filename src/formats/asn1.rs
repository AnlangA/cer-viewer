//! ASN.1 structure viewer.
//!
//! This module provides raw ASN.1 DER structure visualization.

#![allow(dead_code)]

use crate::cert::CertField;
use crate::utils::{describe_oid, format_hex_block};
use oid_registry::Oid;

/// ASN.1 tag classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

/// ASN.1 universal tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UniversalTag {
    EndOfContent = 0,
    Boolean = 1,
    Integer = 2,
    BitString = 3,
    OctetString = 4,
    Null = 5,
    ObjectIdentifier = 6,
    ObjectDescriptor = 7,
    External = 8,
    Real = 9,
    Enumerated = 10,
    EmbeddedPdv = 11,
    Utf8String = 12,
    RelativeOid = 13,
    Sequence = 16,
    Set = 17,
    NumericString = 18,
    PrintableString = 19,
    T61String = 20,
    VideotexString = 21,
    Ia5String = 22,
    UtcTime = 23,
    GeneralizedTime = 24,
    GraphicString = 25,
    VisibleString = 26,
    GeneralString = 27,
    UniversalString = 28,
    CharacterString = 29,
    BmpString = 30,
}

impl UniversalTag {
    fn name(self) -> &'static str {
        match self {
            UniversalTag::EndOfContent => "END-OF-CONTENT",
            UniversalTag::Boolean => "BOOLEAN",
            UniversalTag::Integer => "INTEGER",
            UniversalTag::BitString => "BIT STRING",
            UniversalTag::OctetString => "OCTET STRING",
            UniversalTag::Null => "NULL",
            UniversalTag::ObjectIdentifier => "OBJECT IDENTIFIER",
            UniversalTag::ObjectDescriptor => "OBJECT DESCRIPTOR",
            UniversalTag::External => "EXTERNAL",
            UniversalTag::Real => "REAL",
            UniversalTag::Enumerated => "ENUMERATED",
            UniversalTag::EmbeddedPdv => "EMBEDDED PDV",
            UniversalTag::Utf8String => "UTF8 STRING",
            UniversalTag::RelativeOid => "RELATIVE-OID",
            UniversalTag::Sequence => "SEQUENCE",
            UniversalTag::Set => "SET",
            UniversalTag::NumericString => "NUMERIC STRING",
            UniversalTag::PrintableString => "PRINTABLE STRING",
            UniversalTag::T61String => "T61 STRING",
            UniversalTag::VideotexString => "VIDEOTEX STRING",
            UniversalTag::Ia5String => "IA5 STRING",
            UniversalTag::UtcTime => "UTC TIME",
            UniversalTag::GeneralizedTime => "GENERALIZED TIME",
            UniversalTag::GraphicString => "GRAPHIC STRING",
            UniversalTag::VisibleString => "VISIBLE STRING",
            UniversalTag::GeneralString => "GENERAL STRING",
            UniversalTag::UniversalString => "UNIVERSAL STRING",
            UniversalTag::CharacterString => "CHARACTER STRING",
            UniversalTag::BmpString => "BMP STRING",
        }
    }
}

/// Parsed ASN.1 tag information.
#[derive(Debug, Clone)]
pub struct Asn1Tag {
    /// Tag class
    pub class: TagClass,
    /// Universal tag number (if applicable)
    pub universal_tag: Option<UniversalTag>,
    /// Raw tag byte
    pub raw_tag: u8,
    /// Tag number
    pub number: u32,
    /// Whether this is a constructed tag (contains nested data)
    pub constructed: bool,
}

impl Asn1Tag {
    /// Parse an ASN.1 tag from a single byte.
    fn from_byte(byte: u8) -> Self {
        let class = match (byte & 0xC0) >> 6 {
            0 => TagClass::Universal,
            1 => TagClass::Application,
            2 => TagClass::ContextSpecific,
            _ => TagClass::Private,
        };

        let constructed = (byte & 0x20) != 0;
        let number = (byte & 0x1F) as u32;

        let universal_tag = if class == TagClass::Universal && number <= 30 {
            Some(unsafe { std::mem::transmute::<u8, UniversalTag>(number as u8) })
        } else {
            None
        };

        Self {
            class,
            universal_tag,
            raw_tag: byte,
            number,
            constructed,
        }
    }

    /// Get the tag name.
    pub fn name(&self) -> String {
        if let Some(tag) = self.universal_tag {
            tag.name().to_string()
        } else {
            format!("Tag {}", self.number)
        }
    }
}

/// ASN.1 parse result with offset.
#[derive(Debug, Clone)]
pub struct Asn1ParseResult {
    /// Tag information
    pub tag: Asn1Tag,
    /// Length in bytes
    pub length: usize,
    /// Offset of the content (where data starts)
    pub content_offset: usize,
    /// Offset of the next element
    pub next_offset: usize,
    /// Whether parsing was successful
    pub valid: bool,
}

impl Asn1ParseResult {
    /// Parse length from DER bytes (starting after tag).
    fn parse_length(data: &[u8], offset: &mut usize) -> usize {
        if *offset >= data.len() {
            return 0;
        }

        let first_byte = data[*offset];
        *offset += 1;

        if first_byte & 0x80 == 0 {
            // Short form
            first_byte as usize
        } else {
            // Long form
            let num_bytes = (first_byte & 0x7F) as usize;
            let mut length = 0;
            for _ in 0..num_bytes {
                if *offset < data.len() {
                    length = length * 256 + data[*offset] as usize;
                    *offset += 1;
                }
            }
            length
        }
    }

    /// Parse a single ASN.1 element.
    pub fn parse(data: &[u8], offset: usize) -> Self {
        let _start_offset = offset;

        if offset >= data.len() {
            return Self {
                tag: Asn1Tag::from_byte(0),
                length: 0,
                content_offset: 0,
                next_offset: offset,
                valid: false,
            };
        }

        let tag = Asn1Tag::from_byte(data[offset]);
        let mut current_offset = offset + 1;

        let length = Self::parse_length(data, &mut current_offset);
        let content_offset = current_offset;
        let next_offset = content_offset + length;

        Self {
            tag,
            length,
            content_offset,
            next_offset,
            valid: current_offset <= data.len(),
        }
    }
}

/// View ASN.1 DER structure as a tree of fields.
pub fn view_asn1_structure(data: &[u8]) -> CertField {
    let children = parse_asn1_recursive(data, 0, 0);
    CertField::container("ASN.1 Structure", children)
}

/// Recursively parse ASN.1 structure.
fn parse_asn1_recursive(data: &[u8], offset: usize, depth: usize) -> Vec<CertField> {
    let mut children = Vec::new();
    let max_depth = 10; // Prevent infinite recursion
    let max_elements = 100; // Limit elements per level

    if depth >= max_depth || offset >= data.len() {
        children.push(CertField::leaf("Status", "Max depth or invalid offset"));
        return children;
    }

    let result = Asn1ParseResult::parse(data, offset);

    // Add tag info
    let tag_name = result.tag.name();
    let tag_info = format!(
        "0x{:02X} - {}{}",
        result.tag.raw_tag,
        tag_name,
        if result.tag.constructed {
            " (constructed)"
        } else {
            " (primitive)"
        }
    );
    children.push(CertField::leaf("Tag", tag_info));

    // Add length
    children.push(CertField::leaf(
        "Length",
        format!("{} bytes", result.length),
    ));

    // Add content info
    if result.valid && result.content_offset < data.len() {
        let content_end = result.next_offset.min(data.len());

        if result.tag.constructed {
            // Parse nested elements
            let mut nested_offset = result.content_offset;
            let mut nested_count = 0;
            while nested_offset < content_end && nested_count < max_elements {
                let nested = parse_asn1_recursive(data, nested_offset, depth + 1);
                if nested.is_empty() || nested_offset >= content_end {
                    break;
                }

                // Find the next offset
                let next_result = Asn1ParseResult::parse(data, nested_offset);
                if !next_result.valid || next_result.next_offset > content_end {
                    break;
                }

                // Add nested element as a container
                let nested_label = if nested.len() == 1 {
                    nested[0].label.clone()
                } else {
                    format!("Element {}", nested_count + 1)
                };
                children.push(CertField::container(nested_label, nested));
                nested_offset = next_result.next_offset;
                nested_count += 1;
            }

            // Add remaining bytes preview if any
            if nested_offset < content_end {
                let remaining = &data[nested_offset..content_end];
                let preview = format_hex_block(&hex::encode(remaining));
                children.push(CertField::leaf("Remaining Data", preview));
            }
        } else {
            // Primitive value - show the content
            let content = &data[result.content_offset..content_end];
            let content_str = format_asn1_content(content, &result.tag)
                .unwrap_or_else(|| "(invalid content)".to_string());
            children.push(CertField::leaf("Content", content_str));

            // Also show hex preview
            if !content.is_empty() && content.len() <= 64 {
                let hex_preview = hex::encode(content);
                let formatted = format_hex_block(&hex_preview);
                children.push(CertField::leaf("Hex", formatted));
            }
        }
    } else {
        children.push(CertField::leaf("Status", "Invalid data at this offset"));
    }

    children
}

/// Format ASN.1 content as a string based on tag type.
fn format_asn1_content(data: &[u8], tag: &Asn1Tag) -> Option<String> {
    // Handle NULL specially - it has no content by definition (DER encoding: 0x05 0x00)
    if let Some(UniversalTag::Null) = tag.universal_tag {
        return Some("NULL".to_string());
    }

    if data.is_empty() {
        return Some("(empty)".to_string());
    }

    match tag.universal_tag {
        Some(UniversalTag::ObjectIdentifier) => {
            // Try to parse OID
            if !data.is_empty() && data[0] == 0x06 {
                // Nested OID - just show hex for now
                Some(hex::encode(data))
            } else {
                Some(hex::encode(data))
            }
        }
        Some(UniversalTag::Integer) => {
            // Try to show as decimal
            if data.len() <= 8 {
                let mut value: u64 = 0;
                for &byte in data {
                    value = value * 256 + byte as u64;
                }
                Some(format!("{} (0x{:X})", value, value))
            } else {
                Some(format!("{} bytes", data.len()))
            }
        }
        Some(UniversalTag::Boolean) => {
            if data.len() == 1 {
                Some(if data[0] == 0 { "FALSE" } else { "TRUE" }.to_string())
            } else {
                Some("(invalid boolean)".to_string())
            }
        }
        Some(UniversalTag::Null) => Some("NULL".to_string()),
        Some(UniversalTag::Utf8String)
        | Some(UniversalTag::PrintableString)
        | Some(UniversalTag::VisibleString) => String::from_utf8(data.to_vec())
            .ok()
            .map(|s| format!("\"{}\"", s)),
        Some(UniversalTag::BitString) => Some(format!(
            "{} bits (unused: {})",
            data.len() * 8,
            data.first().map_or(0, |&b| b & 0x07)
        )),
        Some(UniversalTag::UtcTime) | Some(UniversalTag::GeneralizedTime) => {
            // Try to format as time string
            Some(format!("[{} bytes]", data.len()))
        }
        _ => None,
    }
}

/// Try to parse an OID from DER-encoded bytes.
pub fn parse_oid(data: &[u8]) -> Option<String> {
    if data.len() < 2 || data[0] != 0x06 {
        return None;
    }

    // OID encoding: first byte after tag is length
    let oid_bytes = &data[1..];

    // Convert u8 to u64 for the OID registry
    let oid_u64: Vec<u64> = oid_bytes.iter().map(|&b| b as u64).collect();

    // Try to use the OID registry
    if let Ok(oid) = Oid::from(&oid_u64) {
        let desc = describe_oid(&oid);
        Some(format!("{} ({})", oid, desc))
    } else {
        Some(format!("0x{}", hex::encode(oid_bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_view_empty_data() {
        let result = view_asn1_structure(&[]);
        assert_eq!(result.label, "ASN.1 Structure");
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
        // Common OID: 1.2.840.113549.1.1.1 (rsaEncryption)
        let oid_bytes = [
            0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
        ];
        let result = parse_oid(&oid_bytes);
        assert!(result.is_some());
    }

    #[test]
    fn test_tag_parsing() {
        // SEQUENCE tag (0x30)
        let tag = Asn1Tag::from_byte(0x30);
        assert_eq!(tag.class, TagClass::Universal);
        assert_eq!(tag.universal_tag, Some(UniversalTag::Sequence));
        assert_eq!(tag.number, 16);
        assert!(tag.constructed); // SEQUENCE is constructed
        assert_eq!(tag.name(), "SEQUENCE");
    }

    #[test]
    fn test_integer_tag() {
        // INTEGER tag (0x02)
        let tag = Asn1Tag::from_byte(0x02);
        assert_eq!(tag.universal_tag, Some(UniversalTag::Integer));
        assert!(!tag.constructed); // INTEGER is primitive
    }

    #[test]
    fn test_parse_length_short_form() {
        let data = [0x00, 0x05, 1, 2, 3, 4, 5];
        let mut offset = 1;
        let length = Asn1ParseResult::parse_length(&data, &mut offset);
        assert_eq!(length, 5);
    }

    #[test]
    fn test_format_boolean() {
        let true_data = [0xFF];
        let tag = Asn1Tag {
            class: TagClass::Universal,
            universal_tag: Some(UniversalTag::Boolean),
            raw_tag: 0x01,
            number: 1,
            constructed: false,
        };
        let result = format_asn1_content(&true_data, &tag);
        assert_eq!(result, Some("TRUE".to_string()));

        let false_data = [0x00];
        let result = format_asn1_content(&false_data, &tag);
        assert_eq!(result, Some("FALSE".to_string()));
    }

    #[test]
    fn test_format_null() {
        let tag = Asn1Tag {
            class: TagClass::Universal,
            universal_tag: Some(UniversalTag::Null),
            raw_tag: 0x05,
            number: 5,
            constructed: false,
        };
        let result = format_asn1_content(&[], &tag);
        assert_eq!(result, Some("NULL".to_string()));
    }
}
