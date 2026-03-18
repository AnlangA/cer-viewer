//! Command-line interface for cer-viewer.
//!
//! This module provides CLI functionality for viewing certificate information
//! without the GUI, useful for scripting and remote servers.

use crate::cert::{self, CertChain, ParsedCert};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Certificate viewer CLI - Display X.509 certificate information.
#[derive(Parser, Debug)]
#[command(name = "cer-viewer")]
#[command(author = "cer-viewer contributors")]
#[command(version = "0.1.0")]
#[command(about = "A modern X.509 certificate viewer", long_about = None)]
struct Cli {
    /// Certificate file(s) to view (PEM or DER format)
    #[arg(value_name = "FILE")]
    files: Vec<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,

    /// Show certificate chain if multiple certificates are loaded
    #[arg(short, long)]
    chain: bool,

    /// Show only specific fields (comma-separated)
    #[arg(long)]
    fields: Option<String>,

    /// Subcommand for specific operations
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Subcommands for specific certificate operations.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Display certificate chain information
    Chain {
        /// Certificate file(s) to analyze
        #[arg(value_name = "FILE")]
        files: Vec<PathBuf>,
    },
    /// Extract specific field from certificate
    Extract {
        /// Certificate file
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Field name to extract (e.g., subject, issuer, serial)
        #[arg(value_name = "FIELD")]
        field: String,
    },
    /// Verify certificate validity
    Verify {
        /// Certificate file(s) to verify
        #[arg(value_name = "FILE")]
        files: Vec<PathBuf>,
    },
}

/// Output format for certificate information.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, clap::ValueEnum)]
enum OutputFormat {
    /// Human-readable text format (default)
    #[default]
    Text,
    /// JSON format
    Json,
}

/// Run the CLI application.
///
/// Returns `true` if CLI mode was executed (GUI should not start),
/// `false` if no CLI arguments were provided (GUI should start).
pub fn run() -> Result<bool, String> {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            // --help or --version was passed, exit after printing
            e.print().ok();
            return Ok(true);
        }
    };

    // If no files provided and no subcommand, let GUI start
    if cli.files.is_empty() && cli.command.is_none() {
        return Ok(false);
    }

    // Process subcommands first
    if let Some(cmd) = cli.command {
        return run_command(cmd);
    }

    // Load certificates from files
    let mut certs = Vec::new();
    for file in &cli.files {
        match load_certificates_from_file(file) {
            Ok(mut file_certs) => certs.append(&mut file_certs),
            Err(e) => eprintln!("Error loading {}: {}", file.display(), e),
        }
    }

    if certs.is_empty() {
        return Err("No valid certificates found.".to_string());
    }

    // Display based on mode
    if cli.chain {
        display_chain(&certs, cli.format);
    } else {
        display_certificates(&certs, cli.format, cli.fields);
    }

    Ok(true)
}

fn run_command(cmd: Commands) -> Result<bool, String> {
    match cmd {
        Commands::Chain { files } => {
            let mut certs = Vec::new();
            for file in &files {
                match load_certificates_from_file(file) {
                    Ok(mut file_certs) => certs.append(&mut file_certs),
                    Err(e) => eprintln!("Error loading {}: {}", file.display(), e),
                }
            }
            if certs.is_empty() {
                return Err("No valid certificates found.".to_string());
            }
            display_chain(&certs, OutputFormat::Text);
        }
        Commands::Extract { file, field } => {
            let certs = load_certificates_from_file(&file)?;
            if let Some(cert) = certs.first() {
                extract_field(cert, &field);
            } else {
                return Err("No valid certificate found.".to_string());
            }
        }
        Commands::Verify { files } => {
            let mut certs = Vec::new();
            for file in &files {
                match load_certificates_from_file(file) {
                    Ok(mut file_certs) => certs.append(&mut file_certs),
                    Err(e) => eprintln!("Error loading {}: {}", file.display(), e),
                }
            }
            if certs.is_empty() {
                return Err("No valid certificates found.".to_string());
            }
            verify_certificates(&certs);
        }
    }
    Ok(true)
}

fn load_certificates_from_file(path: &PathBuf) -> Result<Vec<ParsedCert>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    let results = cert::parse_certificates(&data);
    let mut certs = Vec::new();

    for result in results {
        match result {
            Ok(cert) => certs.push(cert),
            Err(e) => return Err(format!("Failed to parse certificate: {}", e)),
        }
    }

    Ok(certs)
}

fn display_certificates(certs: &[ParsedCert], format: OutputFormat, fields_filter: Option<String>) {
    match format {
        OutputFormat::Text => {
            for (i, cert) in certs.iter().enumerate() {
                if certs.len() > 1 {
                    println!("Certificate #{}: {}", i + 1, cert.display_name);
                    println!("{}", "=".repeat(60));
                }
                print_certificate_text(cert, &fields_filter);
                if i < certs.len() - 1 {
                    println!();
                }
            }
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(certs).unwrap_or_else(|_| "[]".to_string())
            );
        }
    }
}

fn print_certificate_text(cert: &ParsedCert, fields_filter: &Option<String>) {
    let fields_to_show: Vec<String> = fields_filter
        .as_ref()
        .map(|f| f.split(',').map(|s| s.trim().to_lowercase()).collect())
        .unwrap_or_default();

    // If no specific fields requested, show all
    let show_all = fields_to_show.is_empty();

    // Helper to check if a field should be shown
    let should_show =
        |name: &str| -> bool { show_all || fields_to_show.iter().any(|f| name.contains(f)) };

    if should_show("subject") {
        println!("Subject: {}", cert.subject);
    }
    if should_show("issuer") {
        println!("Issuer: {}", cert.issuer);
    }
    if should_show("serial") || should_show("serial number") {
        println!("Serial Number: {}", cert.serial_number);
    }
    if should_show("valid") || should_show("validity") {
        let status_text = match cert.validity_status {
            cert::ValidityStatus::Valid => "[OK] Valid",
            cert::ValidityStatus::Expired => "[X] Expired",
            cert::ValidityStatus::NotYetValid => "[!] Not Yet Valid",
        };
        println!("Validity: {}", status_text);
        println!("  Not Before: {}", cert.not_before);
        println!("  Not After:  {}", cert.not_after);
    }
    if should_show("fingerprint") {
        println!("SHA-256 Fingerprint: {}", cert.sha256_fingerprint);
        println!("SHA-1 Fingerprint:   {}", cert.sha1_fingerprint);
    }

    // If showing all or extensions requested, show extension count
    if show_all || should_show("extension") {
        let ext_count = cert
            .fields
            .iter()
            .find(|f| f.label == "Extensions")
            .map(|e| e.children.len())
            .unwrap_or(0);
        println!("Extensions: {}", ext_count);
    }

    if show_all {
        // Show all fields as tree
        for field in &cert.fields {
            print_field_tree(field, 0);
        }
    }
}

fn print_field_tree(field: &crate::cert::CertField, depth: usize) {
    let indent = "  ".repeat(depth);
    if let Some(ref value) = field.value {
        println!("{}[{}] {}", indent, field.label, value);
    } else {
        println!("{}[{}]", indent, field.label);
    }
    for child in &field.children {
        print_field_tree(child, depth + 1);
    }
}

fn display_chain(certs: &[ParsedCert], format: OutputFormat) {
    let chain = CertChain::build(certs);

    match format {
        OutputFormat::Text => {
            println!("Certificate Chain");
            println!("{}", "=".repeat(60));

            let status_text = match chain.validation_status {
                crate::cert::ChainValidationStatus::Valid => "✓ Valid",
                crate::cert::ChainValidationStatus::Incomplete { missing_count } => {
                    &format!("⚠ Incomplete ({} missing)", missing_count)
                }
                crate::cert::ChainValidationStatus::BrokenLinks => "✗ Broken Links",
                crate::cert::ChainValidationStatus::Empty => "Empty",
            };
            println!("Status: {}", status_text);
            println!("Length: {} certificate(s)", chain.certificates.len());
            println!();

            for (i, chain_cert) in chain.certificates.iter().enumerate() {
                let position = match chain_cert.position {
                    crate::cert::ChainPosition::Leaf => "Leaf",
                    crate::cert::ChainPosition::Intermediate { .. } => "Intermediate",
                    crate::cert::ChainPosition::Root => "Root CA",
                };
                println!("{}. [{}] {}", i + 1, position, chain_cert.cert.display_name);
                println!("   Subject: {}", chain_cert.cert.subject);
                println!("   Issuer:  {}", chain_cert.cert.issuer);
                println!(
                    "   Valid:   {}",
                    if chain_cert.signature_valid {
                        "✓ Yes"
                    } else {
                        "✗ No"
                    }
                );
                println!();
            }
        }
        OutputFormat::Json => {
            let output = serde_json::json!({
                "validation_status": format!("{:?}", chain.validation_status),
                "certificate_count": chain.certificates.len(),
                "certificates": chain.certificates.iter().map(|cc| {
                    serde_json::json!({
                        "name": cc.cert.display_name,
                        "subject": cc.cert.subject,
                        "issuer": cc.cert.issuer,
                        "position": format!("{:?}", cc.position),
                        "signature_valid": cc.signature_valid,
                    })
                }).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
    }
}

fn extract_field(cert: &ParsedCert, field: &str) {
    let field_lower = field.to_lowercase();

    let result = match field_lower.as_str() {
        "subject" | "s" => cert.subject.clone(),
        "issuer" | "i" => cert.issuer.clone(),
        "serial" | "sn" => cert.serial_number.clone(),
        "sha256" | "fingerprint" | "fp" => cert.sha256_fingerprint.clone(),
        "sha1" => cert.sha1_fingerprint.clone(),
        "not_before" | "nb" => cert.not_before.clone(),
        "not_after" | "na" => cert.not_after.clone(),
        "name" | "cn" => cert.display_name.clone(),
        "pem" => cert.to_pem().trim().to_string(),
        _ => {
            eprintln!("Unknown field: {}", field);
            eprintln!("Available fields: subject, issuer, serial, sha256, sha1, not_before, not_after, name, pem");
            return;
        }
    };

    println!("{}", result);
}

fn verify_certificates(certs: &[ParsedCert]) {
    println!("Certificate Verification");
    println!("{}", "=".repeat(60));
    println!();

    for (i, cert) in certs.iter().enumerate() {
        println!("Certificate #{}: {}", i + 1, cert.display_name);

        // Check validity
        match cert.validity_status {
            cert::ValidityStatus::Valid => {
                println!("  Time validity: ✓ Valid");
            }
            cert::ValidityStatus::Expired => {
                println!("  Time validity: ✗ Expired");
            }
            cert::ValidityStatus::NotYetValid => {
                println!("  Time validity: ✗ Not yet valid");
            }
        }

        // Check self-signed
        let is_self_signed = cert.issuer == cert.subject;
        if is_self_signed {
            println!("  Self-signed: Yes (Root CA)");
        } else {
            println!("  Self-signed: No");
        }

        println!();
    }

    // Chain verification
    if certs.len() > 1 {
        let chain = CertChain::build(certs);
        match chain.validation_status {
            crate::cert::ChainValidationStatus::Valid => {
                println!("Chain verification: ✓ Valid");
            }
            crate::cert::ChainValidationStatus::Incomplete { missing_count } => {
                println!(
                    "Chain verification: ⚠ Incomplete ({} missing certificate(s))",
                    missing_count
                );
            }
            crate::cert::ChainValidationStatus::BrokenLinks => {
                println!("Chain verification: ✗ Broken links");
            }
            crate::cert::ChainValidationStatus::Empty => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_default() {
        let format = OutputFormat::default();
        assert_eq!(format, OutputFormat::Text);
    }

    #[test]
    fn test_extract_field_subject() {
        // This would need a real certificate for a meaningful test
        // For now, just test the function doesn't panic on unknown field
        let cert = create_test_cert();
        // We can't easily test extract_field since it prints to stdout
        // Just verify the cert has expected fields
        assert!(!cert.subject.is_empty());
        assert!(!cert.issuer.is_empty());
    }

    fn create_test_cert() -> ParsedCert {
        ParsedCert {
            id: cert::CertId("test".to_string()),
            display_name: "Test Cert".to_string(),
            serial_number: "00:11:22:33".to_string(),
            sha256_fingerprint: "AA:BB:CC:DD".to_string(),
            sha1_fingerprint: "11:22:33:44".to_string(),
            validity_status: cert::ValidityStatus::Valid,
            not_before: "2024-01-01 00:00:00 UTC".to_string(),
            not_after: "2025-01-01 00:00:00 UTC".to_string(),
            issuer: "CN=Test CA".to_string(),
            subject: "CN=Test".to_string(),
            fields: Vec::new(),
            raw_der: Vec::new(),
        }
    }
}
