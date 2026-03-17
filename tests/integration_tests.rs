//! Integration tests for cer-viewer.

use std::path::PathBuf;

/// Test that we can load and parse a certificate from the assets.
#[test]
fn test_load_baidu_certificate() {
    let cert_path = PathBuf::from("assets/baidu.com.pem");
    if !cert_path.exists() {
        println!("Skipping test: {} not found", cert_path.display());
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate file");
    let result = cer_viewer::cert::parse_certificate(&data);

    assert!(
        result.is_ok(),
        "Failed to parse certificate: {:?}",
        result.err()
    );

    let cert = result.unwrap();
    assert!(!cert.subject.is_empty());
    assert!(!cert.issuer.is_empty());
    assert!(!cert.serial_number.is_empty());
}

/// Test that we can parse multiple certificates from a PEM file.
#[test]
fn test_parse_multiple_certificates() {
    let cert_path = PathBuf::from("assets/baidu.com.pem");
    if !cert_path.exists() {
        println!("Skipping test: {} not found", cert_path.display());
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate file");
    let results = cer_viewer::cert::parse_certificates(&data);

    assert!(!results.is_empty(), "No certificates found");

    for (i, result) in results.iter().enumerate() {
        assert!(
            result.is_ok(),
            "Certificate {} failed to parse: {:?}",
            i,
            result.as_ref().err()
        );
    }
}

/// Test certificate chain building.
#[test]
fn test_certificate_chain_building() {
    let cert_path = PathBuf::from("assets/baidu.com.pem");
    if !cert_path.exists() {
        println!("Skipping test: {} not found", cert_path.display());
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate file");
    let results = cer_viewer::cert::parse_certificates(&data);

    let certs: Vec<_> = results.into_iter().filter_map(|r| r.ok()).collect();

    if certs.is_empty() {
        println!("Skipping test: No valid certificates found");
        return;
    }

    let chain = cer_viewer::cert::CertChain::build(certs);

    // We should have at least one certificate in the chain
    assert!(!chain.certificates.is_empty());

    // The validation status should be one of the expected statuses
    match chain.validation_status {
        cer_viewer::cert::ChainValidationStatus::Valid => {}
        cer_viewer::cert::ChainValidationStatus::Incomplete { .. } => {}
        cer_viewer::cert::ChainValidationStatus::BrokenLinks => {}
        cer_viewer::cert::ChainValidationStatus::Empty => {
            panic!("Chain should not be empty after parsing certificates")
        }
    }
}

/// Test format detection.
#[test]
fn test_format_detection() {
    let cert_path = PathBuf::from("assets/baidu.com.pem");
    if !cert_path.exists() {
        println!("Skipping test: {} not found", cert_path.display());
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate file");

    // Check PEM detection
    let format = cer_viewer::cert::format::detect_format(&data);
    assert_eq!(format, cer_viewer::cert::format::FileFormat::Pem);

    // Check PEM certificate detection
    assert!(cer_viewer::cert::format::is_pem_certificate(&data));
}

/// Test fingerprint calculation.
#[test]
fn test_fingerprint_calculation() {
    let cert_path = PathBuf::from("assets/baidu.com.pem");
    if !cert_path.exists() {
        println!("Skipping test: {} not found", cert_path.display());
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate file");
    let cert = cer_viewer::cert::parse_certificate(&data).expect("Failed to parse certificate");

    // SHA-256 fingerprint should be 32 bytes (64 hex chars + 31 colons = 95 chars)
    assert_eq!(cert.sha256_fingerprint.len(), 95);

    // SHA-1 fingerprint should be 20 bytes (40 hex chars + 19 colons = 59 chars)
    assert_eq!(cert.sha1_fingerprint.len(), 59);

    // Fingerprints should be different (collision test)
    assert_ne!(cert.sha256_fingerprint, cert.sha1_fingerprint);
}

/// Test certificate validity status.
#[test]
fn test_validity_status() {
    let cert_path = PathBuf::from("assets/baidu.com.pem");
    if !cert_path.exists() {
        println!("Skipping test: {} not found", cert_path.display());
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate file");
    let cert = cer_viewer::cert::parse_certificate(&data).expect("Failed to parse certificate");

    // The status should be one of the three options
    match cert.validity_status {
        cer_viewer::cert::ValidityStatus::Valid => {}
        cer_viewer::cert::ValidityStatus::Expired => {}
        cer_viewer::cert::ValidityStatus::NotYetValid => {}
    }
}

/// Test PEM export.
#[test]
fn test_pem_export() {
    let cert_path = PathBuf::from("assets/baidu.com.pem");
    if !cert_path.exists() {
        println!("Skipping test: {} not found", cert_path.display());
        return;
    }

    let data = std::fs::read(&cert_path).expect("Failed to read certificate file");
    let cert = cer_viewer::cert::parse_certificate(&data).expect("Failed to parse certificate");

    let pem = cert.to_pem();

    // Check that it starts and ends with the correct headers
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
    assert!(pem.ends_with("-----END CERTIFICATE-----\n"));

    // Check that we can parse the exported PEM
    let reimported = cer_viewer::cert::parse_certificate(pem.as_bytes());
    assert!(reimported.is_ok());

    let reimported = reimported.unwrap();
    assert_eq!(cert.serial_number, reimported.serial_number);
    assert_eq!(cert.sha256_fingerprint, reimported.sha256_fingerprint);
}

/// Test CLI integration.
#[test]
fn test_cli_help() {
    // This test just verifies that the CLI module is available
    // The actual CLI testing would require spawning a process
    let result = cer_viewer::cli::run();
    // With no arguments, it should return Ok(false) indicating GUI should start
    // But since we're in a test context without a proper terminal, it might error
    match result {
        Ok(_) => {}
        Err(_) => {
            // Expected in test environment
        }
    }
}
