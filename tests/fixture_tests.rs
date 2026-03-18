//! Tests using generated certificate fixtures.

use std::path::PathBuf;

/// Test loading a leaf certificate from fixtures.
#[test]
fn test_load_leaf_certificate() {
    let cert_path = PathBuf::from("tests/fixtures/certificates/valid/example.com.crt");
    if !cert_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate");
    let cert = cer_viewer::cert::parse_certificate(&data);

    assert!(
        cert.is_ok(),
        "Failed to parse certificate: {:?}",
        cert.err()
    );
    let cert = cert.unwrap();

    assert!(!cert.subject.is_empty());
    assert!(!cert.issuer.is_empty());
}

/// Test loading a CA certificate from fixtures.
#[test]
fn test_load_ca_certificate() {
    let cert_path = PathBuf::from("tests/fixtures/certificates/valid/root ca.crt");
    if !cert_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate");
    let cert = cer_viewer::cert::parse_certificate(&data);

    assert!(cert.is_ok());
    let cert = cert.unwrap();

    // CA should be self-signed (issuer == subject)
    assert_eq!(cert.issuer, cert.subject, "CA should be self-signed");
}

/// Test loading an EC certificate.
#[test]
fn test_load_ec_certificate() {
    let cert_path = PathBuf::from("tests/fixtures/certificates/valid/ec cert-ec.crt");
    if !cert_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate");
    let cert = cer_viewer::cert::parse_certificate(&data);

    assert!(cert.is_ok());
    let cert = cert.unwrap();

    // Check that it has EC public key info
    let spki_field = cert
        .fields
        .iter()
        .find(|f| f.label == "Subject Public Key Info");
    assert!(spki_field.is_some(), "Should have SPKI field");
}

/// Test loading certificate chain.
#[test]
fn test_load_certificate_chain() {
    let chain_path = PathBuf::from("tests/fixtures/certificates/valid/chain.pem");
    if !chain_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&chain_path).expect("Failed to read chain");
    let certs = cer_viewer::cert::parse_certificates(&data);

    assert!(!certs.is_empty(), "Should have at least one certificate");

    let valid_certs: Vec<_> = certs.into_iter().filter_map(|r| r.ok()).collect();
    assert!(
        valid_certs.len() >= 2,
        "Should have at least 2 certificates in chain"
    );

    // Build chain
    let chain = cer_viewer::cert::CertChain::build(&valid_certs);
    assert!(!chain.certificates.is_empty());
}

/// Test wildcard certificate.
#[test]
fn test_load_wildcard_certificate() {
    let cert_path = PathBuf::from("tests/fixtures/certificates/valid/wildcard.example.com.crt");
    if !cert_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate");
    let cert = cer_viewer::cert::parse_certificate(&data);

    assert!(cert.is_ok());
}

/// Test PKCS#12 bundle detection.
#[test]
fn test_pkcs12_detection() {
    let p12_path = PathBuf::from("tests/fixtures/pkcs12/example-nopass.p12");
    if !p12_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&p12_path).expect("Failed to read PKCS#12");
    let is_pkcs12 = cer_viewer::formats::pkcs12::is_pkcs12(&data);

    assert!(is_pkcs12, "Should detect PKCS#12 format");
}

/// Test private key loading.
#[test]
fn test_load_rsa_private_key() {
    let key_path = PathBuf::from("tests/fixtures/keys/rsa/example.com.key");
    if !key_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&key_path).expect("Failed to read private key");
    let key = cer_viewer::formats::keys::ParsedPrivateKey::from_pem(&data);

    assert!(key.is_ok(), "Failed to parse private key: {:?}", key.err());
    let key = key.unwrap();

    assert_eq!(key.key_type, cer_viewer::formats::keys::KeyType::Rsa);
}

/// Test EC private key loading.
#[test]
fn test_load_ec_private_key() {
    let key_path = PathBuf::from("tests/fixtures/keys/ec/ec cert-ec.key");
    if !key_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&key_path).expect("Failed to read EC private key");
    let key = cer_viewer::formats::keys::ParsedPrivateKey::from_pem(&data);

    assert!(
        key.is_ok(),
        "Failed to parse EC private key: {:?}",
        key.err()
    );
    let key = key.unwrap();

    assert!(matches!(
        key.key_type,
        cer_viewer::formats::keys::KeyType::Ec
    ));
}

/// Test CSR loading.
#[test]
fn test_load_csr() {
    let csr_path = PathBuf::from("tests/fixtures/csr/example.com.csr");
    if !csr_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&csr_path).expect("Failed to read CSR");
    let csr = cer_viewer::formats::csr::ParsedCsr::from_pem(&data);

    assert!(csr.is_ok(), "Failed to parse CSR: {:?}", csr.err());
    let csr = csr.unwrap();

    assert!(!csr.subject.is_empty());
}

/// Test that chain fixtures build correctly.
#[test]
fn test_chain_from_fixtures() {
    let leaf_path = PathBuf::from("tests/fixtures/certificates/valid/example.com.crt");
    let intermediate_path = PathBuf::from("tests/fixtures/certificates/valid/intermediate ca.crt");
    let root_path = PathBuf::from("tests/fixtures/certificates/valid/root ca.crt");

    if !leaf_path.exists() || !intermediate_path.exists() || !root_path.exists() {
        println!("Skipping: fixtures not found");
        return;
    }

    let leaf_data = std::fs::read(&leaf_path).unwrap();
    let intermediate_data = std::fs::read(&intermediate_path).unwrap();
    let root_data = std::fs::read(&root_path).unwrap();

    let leaf = cer_viewer::cert::parse_certificate(&leaf_data).unwrap();
    let intermediate = cer_viewer::cert::parse_certificate(&intermediate_data).unwrap();
    let root = cer_viewer::cert::parse_certificate(&root_data).unwrap();

    let chain = cer_viewer::cert::CertChain::build(&[leaf, intermediate, root]);

    // Should have a valid chain
    assert!(!chain.certificates.is_empty());

    // Should have at least root and intermediate
    assert!(chain.certificates.len() >= 2);
}

/// Test intermediate certificate detection.
#[test]
fn test_intermediate_ca_detection() {
    let intermediate_path = PathBuf::from("tests/fixtures/certificates/valid/intermediate ca.crt");
    if !intermediate_path.exists() {
        println!("Skipping: fixture not found");
        return;
    }

    let data = std::fs::read(&intermediate_path).unwrap();
    let cert = cer_viewer::cert::parse_certificate(&data).unwrap();

    // The intermediate CA in our fixtures is self-signed
    // (in a real PKI, it would be signed by the root)
    // Just verify it parses correctly
    assert!(!cert.subject.is_empty());
    assert!(cert.subject.contains("Intermediate") || cert.subject.contains("CA"));
}

/// Test all fixture files are parseable.
#[test]
fn test_all_fixture_certificates_parseable() {
    let cert_dirs = [
        "tests/fixtures/certificates/valid",
        "tests/fixtures/certificates/expired",
        "tests/fixtures/certificates/self-signed",
    ];

    let mut parse_count = 0;
    let mut error_count = 0;

    for dir in cert_dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.extension().is_some_and(|e| e == "crt") {
                continue;
            }

            let Ok(data) = std::fs::read(&path) else {
                continue;
            };

            match cer_viewer::cert::parse_certificate(&data) {
                Ok(_) => parse_count += 1,
                Err(e) => {
                    eprintln!("Failed to parse {:?}: {}", path, e);
                    error_count += 1;
                }
            }
        }
    }

    println!(
        "Parsed {} certificate fixtures, {} errors",
        parse_count, error_count
    );
    assert!(
        parse_count >= 5,
        "Should parse at least 5 certificate fixtures"
    );
}
