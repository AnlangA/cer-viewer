//! Certificate extension parsing.
//!
//! This module handles parsing of X.509 certificate extensions into
//! displayable field trees.

use super::{CertField, OID_REGISTRY};
use x509_parser::extensions::{
    AuthorityInfoAccess, AuthorityKeyIdentifier, BasicConstraints, CRLDistributionPoint,
    DistributionPointName, ExtendedKeyUsage, InhibitAnyPolicy, IssuerAlternativeName,
    KeyIdentifier, KeyUsage, NameConstraints, ParsedExtension, PolicyConstraints,
    PolicyInformation, PolicyMappings, SignedCertificateTimestamp, SubjectAlternativeName,
    SubjectInfoAccess,
};
use x509_parser::prelude::*;

/// Build a certificate field from an X.509 extension.
pub fn build_extension_field(ext: &X509Extension<'_>) -> CertField {
    let oid_desc = describe_oid(&ext.oid);
    let critical_str = if ext.critical { " (critical)" } else { "" };
    let label = format!("{oid_desc}{critical_str}");

    let mut children = vec![
        CertField::leaf("OID", ext.oid.to_string()),
        CertField::leaf("Critical", ext.critical.to_string()),
    ];

    match ext.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => {
            parse_san(san, &mut children);
        }
        ParsedExtension::SubjectKeyIdentifier(kid) => {
            parse_ski(kid, &mut children);
        }
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            parse_aki(aki, &mut children);
        }
        ParsedExtension::BasicConstraints(bc) => {
            parse_basic_constraints(bc, &mut children);
        }
        ParsedExtension::KeyUsage(ku) => {
            parse_key_usage(ku, &mut children);
        }
        ParsedExtension::ExtendedKeyUsage(eku) => {
            parse_extended_key_usage(eku, &mut children);
        }
        ParsedExtension::CRLDistributionPoints(crldp) => {
            parse_crl_distribution_points(crldp, &mut children);
        }
        ParsedExtension::AuthorityInfoAccess(aia) => {
            parse_aia(aia, &mut children);
        }
        ParsedExtension::CertificatePolicies(policies) => {
            parse_certificate_policies(policies, &mut children);
        }
        ParsedExtension::SCT(sct_list) => {
            parse_sct_list(sct_list, &mut children);
        }
        ParsedExtension::NameConstraints(nc) => {
            parse_name_constraints(nc, &mut children);
        }
        ParsedExtension::IssuerAlternativeName(ian) => {
            parse_issuer_alt_name(ian, &mut children);
        }
        ParsedExtension::PolicyMappings(pm) => {
            parse_policy_mappings(pm, &mut children);
        }
        ParsedExtension::PolicyConstraints(pc) => {
            parse_policy_constraints(pc, &mut children);
        }
        ParsedExtension::InhibitAnyPolicy(iap) => {
            parse_inhibit_any_policy(iap, &mut children);
        }
        ParsedExtension::SubjectInfoAccess(sia) => {
            parse_subject_info_access(sia, &mut children);
        }
        ParsedExtension::NSCertType(nsct) => {
            parse_ns_cert_type(nsct, &mut children);
        }
        ParsedExtension::NsCertComment(comment) => {
            children.push(CertField::leaf("Comment", comment.to_string()));
        }
        ParsedExtension::UnsupportedExtension { .. } => {
            children.push(CertField::leaf(
                "Raw Value",
                super::format_hex_block(&hex::encode(ext.value)),
            ));
        }
        // Handle all other extensions with raw value display
        other => {
            children.push(CertField::leaf(
                "Raw Value",
                super::format_hex_block(&hex::encode(ext.value)),
            ));
            children.push(CertField::leaf("Type", format!("{other:?}")));
        }
    }

    CertField::container(label, children)
}

// ── Extension parsers ────────────────────────────────────────────────────

fn parse_san(san: &SubjectAlternativeName<'_>, children: &mut Vec<CertField>) {
    let names: Vec<CertField> = san
        .general_names
        .iter()
        .map(|gn| CertField::leaf("Name", format_general_name(gn)))
        .collect();
    children.push(CertField::container("Alternative Names", names));
}

fn parse_ski(kid: &KeyIdentifier<'_>, children: &mut Vec<CertField>) {
    children.push(CertField::leaf(
        "Key Identifier",
        super::format_hex_block(&hex::encode(kid.0)),
    ));
}

fn parse_aki(aki: &AuthorityKeyIdentifier<'_>, children: &mut Vec<CertField>) {
    if let Some(kid) = &aki.key_identifier {
        children.push(CertField::leaf(
            "Key Identifier",
            super::format_hex_block(&hex::encode(kid.0)),
        ));
    }
    if let Some(issuer) = &aki.authority_cert_issuer {
        let issuers: String = issuer
            .iter()
            .map(format_general_name)
            .collect::<Vec<_>>()
            .join(", ");
        children.push(CertField::leaf("Authority Cert Issuer", issuers));
    }
    if let Some(serial) = &aki.authority_cert_serial {
        children.push(CertField::leaf(
            "Authority Cert Serial Number",
            super::format_hex_block(&hex::encode(serial)),
        ));
    }
}

fn parse_basic_constraints(bc: &BasicConstraints, children: &mut Vec<CertField>) {
    children.push(CertField::leaf("CA", bc.ca.to_string()));
    if let Some(len) = bc.path_len_constraint {
        children.push(CertField::leaf("Path Length", len.to_string()));
    }
}

type KeyUsageChecker = fn(&KeyUsage) -> bool;
type EkuChecker = fn(&ExtendedKeyUsage) -> bool;

fn parse_key_usage(ku: &KeyUsage, children: &mut Vec<CertField>) {
    const KEY_USAGE_FLAGS: &[(&str, KeyUsageChecker)] = &[
        ("Digital Signature", |k| k.digital_signature()),
        ("Non Repudiation (Content Commitment)", |k| {
            k.non_repudiation()
        }),
        ("Key Encipherment", |k| k.key_encipherment()),
        ("Data Encipherment", |k| k.data_encipherment()),
        ("Key Agreement", |k| k.key_agreement()),
        ("Key Cert Sign", |k| k.key_cert_sign()),
        ("CRL Sign", |k| k.crl_sign()),
        ("Encipher Only", |k| k.encipher_only()),
        ("Decipher Only", |k| k.decipher_only()),
    ];

    let flags: Vec<&str> = KEY_USAGE_FLAGS
        .iter()
        .filter(|(_, check)| check(ku))
        .map(|(name, _)| *name)
        .collect();

    children.push(CertField::leaf("Usages", flags.join(", ")));
}

fn parse_extended_key_usage(eku: &ExtendedKeyUsage, children: &mut Vec<CertField>) {
    const EKU_FLAGS: &[(&str, EkuChecker)] = &[
        ("Server Auth", |e| e.server_auth),
        ("Client Auth", |e| e.client_auth),
        ("Code Signing", |e| e.code_signing),
        ("Email Protection", |e| e.email_protection),
        ("Time Stamping", |e| e.time_stamping),
        ("OCSP Signing", |e| e.ocsp_signing),
        ("Any", |e| e.any),
    ];

    let mut usages: Vec<String> = EKU_FLAGS
        .iter()
        .filter(|(_, check)| check(eku))
        .map(|(name, _)| name.to_string())
        .collect();

    for oid in &eku.other {
        usages.push(describe_oid(oid));
    }

    let usages_str: String = usages.join(", ");
    children.push(CertField::leaf("Usages", usages_str));
}

fn parse_crl_distribution_points(crldp: &[CRLDistributionPoint], children: &mut Vec<CertField>) {
    for (i, dp) in crldp.iter().enumerate() {
        let mut dp_children = Vec::new();

        if let Some(dn) = &dp.distribution_point {
            let desc = match dn {
                DistributionPointName::FullName(names) => names
                    .iter()
                    .map(format_general_name)
                    .collect::<Vec<_>>()
                    .join(", "),
                DistributionPointName::NameRelativeToCRLIssuer(rdn) => format!("{rdn:?}"),
            };
            dp_children.push(CertField::leaf("Location", desc));
        }

        if let Some(reasons) = &dp.reasons {
            let mut reason_list = Vec::new();
            if reasons.key_compromise() {
                reason_list.push("Key Compromise");
            }
            if reasons.ca_compromise() {
                reason_list.push("CA Compromise");
            }
            if reasons.affilation_changed() {
                reason_list.push("Affiliation Changed");
            }
            if reasons.superseded() {
                reason_list.push("Superseded");
            }
            if reasons.cessation_of_operation() {
                reason_list.push("Cessation of Operation");
            }
            if reasons.certificate_hold() {
                reason_list.push("Certificate Hold");
            }
            if reasons.privelege_withdrawn() {
                reason_list.push("Privilege Withdrawn");
            }
            if reasons.aa_compromise() {
                reason_list.push("AA Compromise");
            }
            dp_children.push(CertField::leaf("Reasons", reason_list.join(", ")));
        }

        if let Some(issuer) = &dp.crl_issuer {
            let issuers: String = issuer
                .iter()
                .map(format_general_name)
                .collect::<Vec<_>>()
                .join(", ");
            dp_children.push(CertField::leaf("CRL Issuer", issuers));
        }

        if !dp_children.is_empty() {
            children.push(CertField::container(
                format!("Distribution Point {}", i + 1),
                dp_children,
            ));
        }
    }
}

fn parse_aia(aia: &AuthorityInfoAccess, children: &mut Vec<CertField>) {
    for desc in &aia.accessdescs {
        let method = describe_oid(&desc.access_method);
        let location = format_general_name(&desc.access_location);
        children.push(CertField::leaf(method, location));
    }
}

fn parse_certificate_policies(policies: &[PolicyInformation], children: &mut Vec<CertField>) {
    for (i, pol) in policies.iter().enumerate() {
        let mut policy_children = vec![CertField::leaf(
            "Policy Identifier",
            describe_oid(&pol.policy_id),
        )];

        if let Some(qualifiers) = &pol.policy_qualifiers {
            let qualifier_fields: Vec<CertField> = qualifiers
                .iter()
                .enumerate()
                .map(|(j, q)| {
                    let qid = describe_oid(&q.policy_qualifier_id);
                    // The qualifier is &[u8] - try to decode as string
                    let value = if let Ok(s) = std::str::from_utf8(q.qualifier) {
                        // Clean up the string if it looks like text
                        s.chars()
                            .filter(|c| c.is_ascii_graphic() || *c == ' ')
                            .collect::<String>()
                    } else {
                        super::format_hex_block(&hex::encode(q.qualifier))
                    };
                    CertField::leaf(format!("Qualifier {} ({})", j + 1, qid), value)
                })
                .collect();
            policy_children.push(CertField::container("Policy Qualifiers", qualifier_fields));
        }

        children.push(CertField::container(
            format!("Policy {}", i + 1),
            policy_children,
        ));
    }
}

fn parse_sct_list(sct_list: &[SignedCertificateTimestamp], children: &mut Vec<CertField>) {
    for (i, sct) in sct_list.iter().enumerate() {
        let mut sct_children = vec![
            CertField::leaf("Version", format!("v{}", sct.version.0 + 1)),
            CertField::leaf(
                "Log ID",
                super::format_hex_block(&hex::encode(sct.id.key_id)),
            ),
            CertField::leaf("Timestamp", format_sct_timestamp(sct.timestamp)),
        ];

        // Add extensions if present
        if !sct.extensions.0.is_empty() {
            sct_children.push(CertField::leaf(
                "Extensions",
                super::format_hex_block(&hex::encode(sct.extensions.0)),
            ));
        }

        // Add signature algorithm and value
        let sig_alg =
            describe_sct_signature_algorithm(sct.signature.hash_alg_id, sct.signature.sign_alg_id);
        sct_children.push(CertField::leaf("Signature Algorithm", sig_alg));
        sct_children.push(CertField::leaf(
            "Signature Value",
            super::format_hex_block(&hex::encode(sct.signature.data)),
        ));

        children.push(CertField::container(format!("SCT {}", i + 1), sct_children));
    }
}

fn format_sct_timestamp(timestamp: u64) -> String {
    // SCT timestamp is milliseconds since Unix epoch
    use chrono::{TimeZone, Utc};
    let secs = (timestamp / 1000) as i64;
    let millis = (timestamp % 1000) as u32;
    match Utc.timestamp_opt(secs, millis * 1_000_000) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
        _ => format!("{} ms", timestamp),
    }
}

fn describe_sct_signature_algorithm(hash_alg: u8, sign_alg: u8) -> String {
    let hash = match hash_alg {
        0 => "None",
        1 => "MD5",
        2 => "SHA1",
        3 => "SHA224",
        4 => "SHA256",
        5 => "SHA384",
        6 => "SHA512",
        _ => "Unknown",
    };
    let sign = match sign_alg {
        0 => "Anonymous",
        1 => "RSA",
        2 => "DSA",
        3 => "ECDSA",
        _ => "Unknown",
    };
    format!("{}_{}", hash, sign)
}

// ── New extension parsers ────────────────────────────────────────────────────

fn parse_name_constraints(nc: &NameConstraints<'_>, children: &mut Vec<CertField>) {
    if let Some(permitted) = &nc.permitted_subtrees {
        let permitted_fields: Vec<CertField> = permitted
            .iter()
            .enumerate()
            .map(|(i, subtree)| {
                CertField::leaf(
                    format!("Permitted {}", i + 1),
                    format_general_name(&subtree.base),
                )
            })
            .collect();
        children.push(CertField::container("Permitted Subtrees", permitted_fields));
    }

    if let Some(excluded) = &nc.excluded_subtrees {
        let excluded_fields: Vec<CertField> = excluded
            .iter()
            .enumerate()
            .map(|(i, subtree)| {
                CertField::leaf(
                    format!("Excluded {}", i + 1),
                    format_general_name(&subtree.base),
                )
            })
            .collect();
        children.push(CertField::container("Excluded Subtrees", excluded_fields));
    }
}

fn parse_issuer_alt_name(ian: &IssuerAlternativeName<'_>, children: &mut Vec<CertField>) {
    let names: Vec<CertField> = ian
        .general_names
        .iter()
        .map(|gn| CertField::leaf("Name", format_general_name(gn)))
        .collect();
    children.push(CertField::container("Alternative Names", names));
}

fn parse_policy_mappings(pm: &PolicyMappings<'_>, children: &mut Vec<CertField>) {
    let mappings: Vec<CertField> = pm
        .mappings
        .iter()
        .enumerate()
        .map(|(i, mapping)| {
            CertField::container(
                format!("Mapping {}", i + 1),
                vec![
                    CertField::leaf(
                        "Issuer Domain Policy",
                        describe_oid(&mapping.issuer_domain_policy),
                    ),
                    CertField::leaf(
                        "Subject Domain Policy",
                        describe_oid(&mapping.subject_domain_policy),
                    ),
                ],
            )
        })
        .collect();
    children.push(CertField::container("Policy Mappings", mappings));
}

fn parse_policy_constraints(pc: &PolicyConstraints, children: &mut Vec<CertField>) {
    if let Some(require_explicit) = pc.require_explicit_policy {
        children.push(CertField::leaf(
            "Require Explicit Policy",
            require_explicit.to_string(),
        ));
    }
    if let Some(inhibit_mapping) = pc.inhibit_policy_mapping {
        children.push(CertField::leaf(
            "Inhibit Policy Mapping",
            inhibit_mapping.to_string(),
        ));
    }
}

fn parse_inhibit_any_policy(iap: &InhibitAnyPolicy, children: &mut Vec<CertField>) {
    children.push(CertField::leaf(
        "Skip Certificates",
        iap.skip_certs.to_string(),
    ));
}

fn parse_subject_info_access(sia: &SubjectInfoAccess<'_>, children: &mut Vec<CertField>) {
    for desc in &sia.accessdescs {
        let method = describe_oid(&desc.access_method);
        let location = format_general_name(&desc.access_location);
        children.push(CertField::leaf(method, location));
    }
}

fn parse_ns_cert_type(nsct: &x509_parser::extensions::NSCertType, children: &mut Vec<CertField>) {
    let mut usages: Vec<&str> = Vec::new();
    if nsct.ssl_client() {
        usages.push("SSL Client");
    }
    if nsct.ssl_server() {
        usages.push("SSL Server");
    }
    if nsct.smime() {
        usages.push("S/MIME");
    }
    if nsct.object_signing() {
        usages.push("Object Signing");
    }
    if nsct.ssl_ca() {
        usages.push("SSL CA");
    }
    if nsct.smime_ca() {
        usages.push("S/MIME CA");
    }
    if nsct.object_signing_ca() {
        usages.push("Object Signing CA");
    }

    children.push(CertField::leaf("Usages", usages.join(", ")));
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn describe_oid(oid: &oid_registry::Oid<'_>) -> String {
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

fn format_general_name(gn: &GeneralName<'_>) -> String {
    match gn {
        GeneralName::DNSName(s) => format!("DNS: {s}"),
        GeneralName::RFC822Name(s) => format!("Email: {s}"),
        GeneralName::URI(s) => format!("URI: {s}"),
        GeneralName::IPAddress(bytes) => {
            if bytes.len() == 4 {
                format!("IP: {}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
            } else if bytes.len() == 16 {
                format!("IP: {}", format_ipv6(bytes))
            } else if bytes.len() == 8 {
                // IPv4 with netmask
                format!(
                    "IP: {}.{}.{}.{}/{}.{}.{}.{}",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]
                )
            } else if bytes.len() == 32 {
                // IPv6 with netmask
                format!(
                    "IP: {}/{}",
                    format_ipv6(&bytes[..16]),
                    format_ipv6(&bytes[16..])
                )
            } else {
                format!("IP: {}", hex::encode(bytes))
            }
        }
        GeneralName::DirectoryName(name) => format!("DN: {name}"),
        GeneralName::OtherName(oid, _) => format!("OtherName: {} [...]", describe_oid(oid)),
        GeneralName::RegisteredID(oid) => format!("Registered ID: {}", describe_oid(oid)),
        GeneralName::X400Address(_) => "X400Address: (not decoded)".to_string(),
        GeneralName::EDIPartyName(_) => "EDIPartyName: (not decoded)".to_string(),
        GeneralName::Invalid(tag, data) => {
            format!("Invalid: tag={} data={}", tag, hex::encode(data))
        }
    }
}

fn format_ipv6(bytes: &[u8]) -> String {
    assert!(bytes.len() == 16, "IPv6 must be 16 bytes");
    let segments: Vec<String> = bytes
        .chunks(2)
        .map(|chunk| format!("{:02x}{:02x}", chunk[0], chunk[1]))
        .collect();
    segments.join(":")
}
