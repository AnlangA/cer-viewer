//! CLI integration tests for cer-viewer.
//!
//! These tests verify the CLI mode functionality including
//! certificate parsing, output formats, and error handling.

use std::path::PathBuf;
use std::process::Command;

/// Get the path to the cer-viewer binary.
#[allow(dead_code)] // Reserved for future direct binary testing
fn cer_viewer_bin() -> PathBuf {
    // During development, use cargo run
    // In CI, use the built binary
    if std::path::Path::new("target/debug/cer-viewer").exists() {
        PathBuf::from("target/debug/cer-viewer")
    } else if std::path::Path::new("target/release/cer-viewer").exists() {
        PathBuf::from("target/release/cer-viewer")
    } else {
        // Fall back to cargo run
        PathBuf::from("cargo")
    }
}

/// Get the path to test assets.
fn asset_path(name: &str) -> PathBuf {
    PathBuf::from(format!("assets/{}", name))
}

#[test]
fn test_cli_help() {
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("certificate"));
    assert!(stdout.contains("OPTIONS"));
}

#[test]
fn test_cli_version() {
    let output = Command::new("cargo")
        .args(["run", "--", "--version"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("cer-viewer"));
}

#[test]
fn test_cli_display_certificate() {
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        // Skip if asset not available
        return;
    }

    let output = Command::new("cargo")
        .args(["run", "--", cert_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Subject"));
    assert!(stdout.contains("Issuer"));
    assert!(stdout.contains("Serial Number"));
}

#[test]
fn test_cli_json_output() {
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        return;
    }

    let output = Command::new("cargo")
        .args(["run", "--", "--format", "json", cert_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should be valid JSON
    assert!(stdout.contains('{') || stdout.contains('['));
}

#[test]
fn test_cli_extract_subject() {
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        return;
    }

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "extract",
            cert_path.to_str().unwrap(),
            "subject",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should output a subject DN
    assert!(!stdout.trim().is_empty());
}

#[test]
fn test_cli_extract_serial() {
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        return;
    }

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "extract",
            cert_path.to_str().unwrap(),
            "serial",
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should output a serial number (hex format)
    assert!(!stdout.trim().is_empty());
}

#[test]
fn test_cli_chain_mode() {
    // Test chain mode with a certificate file
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        return;
    }

    let output = Command::new("cargo")
        .args(["run", "--", "--chain", cert_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Chain") || stdout.contains("chain"));
}

#[test]
fn test_cli_verify_mode() {
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        return;
    }

    let output = Command::new("cargo")
        .args(["run", "--", "verify", cert_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Verification") || stdout.contains("valid"));
}

#[test]
fn test_cli_field_filter() {
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        return;
    }

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "--fields",
            "subject,issuer",
            cert_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Subject"));
    assert!(stdout.contains("Issuer"));
}

#[test]
fn test_cli_invalid_file() {
    let output = Command::new("cargo")
        .args(["run", "--", "/nonexistent/file.pem"])
        .output()
        .unwrap();

    // Should fail with an error message
    assert!(!output.status.success() || String::from_utf8_lossy(&output.stderr).contains("Error"));
}

#[test]
fn test_cli_invalid_certificate() {
    // Create a temporary invalid file
    let temp_dir = std::env::temp_dir();
    let invalid_cert = temp_dir.join("invalid_cert.pem");
    std::fs::write(&invalid_cert, "NOT A CERTIFICATE").unwrap();

    let output = Command::new("cargo")
        .args(["run", "--", invalid_cert.to_str().unwrap()])
        .output()
        .unwrap();

    // Should fail gracefully
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!output.status.success() || stderr.contains("Error") || stdout.contains("Error"));

    // Clean up
    let _ = std::fs::remove_file(invalid_cert);
}

#[test]
fn test_cli_extract_invalid_field() {
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        return;
    }

    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "extract",
            cert_path.to_str().unwrap(),
            "nonexistent_field",
        ])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Unknown field") || stderr.contains("Available fields"));
}

#[test]
fn test_cli_pem_export_field() {
    let cert_path = asset_path("baidu.com.pem");
    if !cert_path.exists() {
        return;
    }

    let output = Command::new("cargo")
        .args(["run", "--", "extract", cert_path.to_str().unwrap(), "pem"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("-----BEGIN CERTIFICATE-----"));
    assert!(stdout.contains("-----END CERTIFICATE-----"));
}
