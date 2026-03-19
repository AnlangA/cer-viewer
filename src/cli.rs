//! Command-line interface for cer-viewer.
//!
//! This module provides CLI functionality for viewing certificate and CSR
//! information without the GUI, useful for scripting and remote servers.

use crate::cert::{self, CertChain, CertField, ParsedCert};
use crate::document::Document;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Certificate viewer CLI - Display X.509 certificate and CSR information.
#[derive(Parser, Debug)]
#[command(name = "cer-viewer")]
#[command(author = "cer-viewer contributors")]
#[command(version = "0.1.0")]
#[command(about = "A modern X.509 certificate and CSR viewer", long_about = None)]
struct Cli {
    /// Certificate or CSR file(s) to view (PEM or DER format)
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
        /// Certificate or CSR file
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
    /// Convert certificate between PEM and DER formats
    Convert {
        /// Input certificate file
        #[arg(value_name = "INPUT")]
        input: PathBuf,
        /// Output file path
        #[arg(value_name = "OUTPUT")]
        output: PathBuf,
        /// Target format (pem or der)
        #[arg(long, value_enum, default_value_t = ConvertFormat::Pem)]
        to: ConvertFormat,
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

/// Target format for the `convert` subcommand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum ConvertFormat {
    /// PEM format (base64-encoded with header/footer lines)
    Pem,
    /// DER format (binary ASN.1)
    Der,
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

    // Load documents from files
    let mut documents = Vec::new();
    for file in &cli.files {
        match load_documents_from_file(file) {
            Ok(mut file_docs) => documents.append(&mut file_docs),
            Err(e) => eprintln!("Error loading {}: {}", file.display(), e),
        }
    }

    if documents.is_empty() {
        return Err("No valid certificates or CSRs found.".to_string());
    }

    // Display based on mode
    if cli.chain {
        let certs: Vec<ParsedCert> = documents
            .into_iter()
            .filter_map(|d| match d {
                Document::Certificate(c) => Some(c),
                _ => None,
            })
            .collect();
        if certs.is_empty() {
            return Err("Chain view requires certificates, not CSRs.".to_string());
        }
        display_chain(&certs, cli.format);
    } else {
        display_documents(&documents, cli.format, cli.fields);
    }

    Ok(true)
}

fn run_command(cmd: Commands) -> Result<bool, String> {
    match cmd {
        Commands::Chain { files } => {
            let mut certs = Vec::new();
            for file in &files {
                let docs = load_documents_from_file(file)?;
                for doc in docs {
                    if let Document::Certificate(cert) = doc {
                        certs.push(cert);
                    }
                }
            }
            if certs.is_empty() {
                return Err("No valid certificates found.".to_string());
            }
            display_chain(&certs, OutputFormat::Text);
        }
        Commands::Extract { file, field } => {
            let docs = load_documents_from_file(&file)?;
            if let Some(doc) = docs.first() {
                extract_field(doc, &field);
            } else {
                return Err("No valid certificate or CSR found.".to_string());
            }
        }
        Commands::Verify { files } => {
            let mut certs = Vec::new();
            for file in &files {
                let docs = load_documents_from_file(file)?;
                for doc in docs {
                    if let Document::Certificate(cert) = doc {
                        certs.push(cert);
                    }
                }
            }
            if certs.is_empty() {
                return Err("No valid certificates found.".to_string());
            }
            verify_certificates(&certs);
        }
        Commands::Convert { input, output, to } => {
            convert_certificate(&input, &output, to)?;
        }
    }
    Ok(true)
}

fn load_documents_from_file(path: &PathBuf) -> Result<Vec<Document>, String> {
    let data = std::fs::read(path).map_err(|e| format!("Failed to read file: {}", e))?;

    let results = crate::document::load_documents(&data);
    let mut docs = Vec::new();
    let mut errors = Vec::new();

    for result in &results {
        match result {
            Ok(doc) => docs.push(doc.clone()),
            Err(e) => errors.push(e.clone()),
        }
    }

    if docs.is_empty() && !errors.is_empty() {
        return Err(errors[0].clone());
    }

    Ok(docs)
}

fn display_documents(docs: &[Document], format: OutputFormat, fields_filter: Option<String>) {
    match format {
        OutputFormat::Text => {
            for (i, doc) in docs.iter().enumerate() {
                let type_label = if doc.is_csr() { "CSR" } else { "Certificate" };
                if docs.len() > 1 {
                    println!("{} #{}: {}", type_label, i + 1, doc.display_name());
                    println!("{}", "=".repeat(60));
                }
                print_document_text(doc, &fields_filter);
                if i < docs.len() - 1 {
                    println!();
                }
            }
        }
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(docs).unwrap_or_else(|_| "[]".to_string())
            );
        }
    }
}

fn print_document_text(doc: &Document, fields_filter: &Option<String>) {
    match doc {
        Document::Certificate(cert) => print_certificate_text(cert, fields_filter),
        Document::Csr(csr) => print_csr_text(csr, fields_filter),
    }
}

fn print_certificate_text(cert: &ParsedCert, fields_filter: &Option<String>) {
    let fields_to_show: Vec<String> = fields_filter
        .as_ref()
        .map(|f| f.split(',').map(|s| s.trim().to_lowercase()).collect())
        .unwrap_or_default();

    let show_all = fields_to_show.is_empty();
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
        for field in &cert.fields {
            print_field_tree(field, 0);
        }
    }
}

fn print_csr_text(csr: &crate::formats::csr::ParsedCsr, fields_filter: &Option<String>) {
    let fields_to_show: Vec<String> = fields_filter
        .as_ref()
        .map(|f| f.split(',').map(|s| s.trim().to_lowercase()).collect())
        .unwrap_or_default();

    let show_all = fields_to_show.is_empty();
    let should_show =
        |name: &str| -> bool { show_all || fields_to_show.iter().any(|f| name.contains(f)) };

    println!("[CSR]");
    if should_show("subject") {
        println!("Subject: {}", csr.subject);
    }
    if should_show("signature") || should_show("signature algorithm") {
        println!("Signature Algorithm: {}", csr.signature_algorithm);
    }
    if should_show("fingerprint") {
        println!("SHA-256 Fingerprint: {}", csr.sha256_fingerprint);
        println!("SHA-1 Fingerprint:   {}", csr.sha1_fingerprint);
    }

    if show_all || should_show("extension") {
        let ext_count = csr
            .fields
            .iter()
            .find(|f| f.label == "Attributes")
            .and_then(|a| a.children.iter().find(|c| c.label == "Extension Request"))
            .map(|er| er.children.len())
            .unwrap_or(0);
        println!("Extensions: {}", ext_count);
    }

    if show_all {
        for field in &csr.fields {
            print_field_tree(field, 0);
        }
    }
}

fn print_field_tree(field: &CertField, depth: usize) {
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
    let chain = build_and_complete_chain(certs);

    match format {
        OutputFormat::Text => {
            println!("Certificate Chain");
            println!("{}", "=".repeat(60));

            let status_text = match chain.validation_status {
                crate::cert::ChainValidationStatus::Valid => "Valid",
                crate::cert::ChainValidationStatus::Incomplete { missing_count } => {
                    &format!("Incomplete ({} missing)", missing_count)
                }
                crate::cert::ChainValidationStatus::BrokenLinks => "Broken Links",
                crate::cert::ChainValidationStatus::Empty => "Empty",
            };
            println!("Status: {}", status_text);
            println!("Length: {} certificate(s)", chain.certificates.len());
            #[cfg(feature = "network")]
            if let Some(ref err) = chain.completion_error {
                println!("Completion Error: {}", err);
            }
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
                    "   Signature: {}",
                    match chain_cert.signature_status {
                        crate::cert::SignatureStatus::Valid => "Valid",
                        crate::cert::SignatureStatus::Invalid => "Invalid",
                        crate::cert::SignatureStatus::Unknown => "Unknown (issuer missing)",
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
                        "signature_status": format!("{:?}", cc.signature_status),
                    })
                }).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        }
    }
}

/// Build a chain and optionally complete it via AIA downloads.
fn build_and_complete_chain(certs: &[ParsedCert]) -> CertChain {
    let chain = CertChain::build(certs.to_vec());
    #[cfg(feature = "network")]
    let chain = chain.complete_chain();
    chain
}

fn extract_field(doc: &Document, field: &str) {
    let field_lower = field.to_lowercase();

    let result = match doc {
        Document::Certificate(cert) => match field_lower.as_str() {
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
                eprintln!(
                    "Available fields: subject, issuer, serial, sha256, sha1, not_before, not_after, name, pem"
                );
                return;
            }
        },
        Document::Csr(csr) => match field_lower.as_str() {
            "subject" | "s" | "name" | "cn" => csr.subject.clone(),
            "sha256" | "fingerprint" | "fp" => csr.sha256_fingerprint.clone(),
            "sha1" => csr.sha1_fingerprint.clone(),
            "signature" | "sig" => csr.signature_algorithm.clone(),
            "pem" => csr.to_pem().trim().to_string(),
            _ => {
                eprintln!("Unknown field: {}", field);
                eprintln!("Available CSR fields: subject, sha256, sha1, signature, pem");
                return;
            }
        },
    };

    println!("{}", result);
}

fn verify_certificates(certs: &[ParsedCert]) {
    println!("Certificate Verification");
    println!("{}", "=".repeat(60));
    println!();

    for (i, cert) in certs.iter().enumerate() {
        println!("Certificate #{}: {}", i + 1, cert.display_name);

        match cert.validity_status {
            cert::ValidityStatus::Valid => {
                println!("  Time validity: Valid");
            }
            cert::ValidityStatus::Expired => {
                println!("  Time validity: Expired");
            }
            cert::ValidityStatus::NotYetValid => {
                println!("  Time validity: Not yet valid");
            }
        }

        let is_self_signed = cert.issuer == cert.subject;
        if is_self_signed {
            println!("  Self-signed: Yes (Root CA)");
        } else {
            println!("  Self-signed: No");
        }

        println!();
    }

    if certs.len() > 1 {
        let chain = build_and_complete_chain(certs);
        match chain.validation_status {
            crate::cert::ChainValidationStatus::Valid => {
                println!("Chain verification: Valid");
            }
            crate::cert::ChainValidationStatus::Incomplete { missing_count } => {
                println!(
                    "Chain verification: Incomplete ({} missing certificate(s))",
                    missing_count
                );
            }
            crate::cert::ChainValidationStatus::BrokenLinks => {
                println!("Chain verification: Broken links");
            }
            crate::cert::ChainValidationStatus::Empty => {}
        }
        #[cfg(feature = "network")]
        if let Some(ref err) = chain.completion_error {
            println!("Chain completion error: {}", err);
        }
    }
}

/// Convert a certificate file between PEM and DER formats.
///
/// Reads `input`, auto-detects its current format, converts to `target`,
/// and writes the result to `output`.
fn convert_certificate(
    input: &PathBuf,
    output: &PathBuf,
    target: ConvertFormat,
) -> Result<(), String> {
    let data =
        std::fs::read(input).map_err(|e| format!("Failed to read '{}': {e}", input.display()))?;

    let output_data: Vec<u8> = match target {
        ConvertFormat::Der => {
            // Input is PEM → convert to DER.
            if data.starts_with(b"-----") {
                crate::export::pem_to_der(&data)
                    .map_err(|e| format!("PEM → DER conversion failed: {e}"))?
            } else {
                // Already DER – write as-is.
                data
            }
        }
        ConvertFormat::Pem => {
            // Input is DER → wrap in PEM.
            if data.starts_with(b"-----") {
                // Already PEM – write as-is.
                data
            } else {
                // Detect what kind of DER object this is by attempting a parse.
                let label = detect_der_label(&data);
                crate::export::to_pem(label, &data).into_bytes()
            }
        }
    };

    std::fs::write(output, &output_data)
        .map_err(|e| format!("Failed to write '{}': {e}", output.display()))?;

    println!(
        "Converted '{}' → '{}' ({})",
        input.display(),
        output.display(),
        match target {
            ConvertFormat::Der => "DER",
            ConvertFormat::Pem => "PEM",
        }
    );

    Ok(())
}

/// Heuristically determine the PEM label for a DER blob by trying to parse it
/// as common certificate and key types.
fn detect_der_label(data: &[u8]) -> &'static str {
    // Try X.509 certificate (most common case).
    if crate::cert::parse_der_certificate(data).is_ok() {
        return "CERTIFICATE";
    }

    // Try CSR (PKCS#10 CertificationRequest).
    #[cfg(feature = "pkcs12")]
    if crate::formats::csr::is_der_csr(data) {
        return "CERTIFICATE REQUEST";
    }

    // Try PKCS#8 private key.
    #[cfg(feature = "private-keys")]
    if crate::formats::keys::is_pkcs8_private_key(data) {
        return "PRIVATE KEY";
    }

    // Try EC private key (SEC1).
    #[cfg(feature = "private-keys")]
    if crate::formats::keys::is_ec_private_key(data) {
        return "EC PRIVATE KEY";
    }

    // Try RSA private key (PKCS#1).
    #[cfg(feature = "private-keys")]
    if crate::formats::keys::is_rsa_private_key(data) {
        return "RSA PRIVATE KEY";
    }

    // Default: treat as a generic certificate.
    "CERTIFICATE"
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
        let docs = crate::document::load_documents(include_bytes!("../assets/baidu.com.pem"));
        assert!(docs[0].as_ref().is_ok());
        let doc = docs[0].as_ref().unwrap();
        assert!(!doc.subject().is_empty());
    }

    #[test]
    fn test_extract_field_from_csr() {
        let docs = crate::document::load_documents(include_bytes!("../assets/test.csr"));
        assert!(docs[0].as_ref().is_ok());
        let doc = docs[0].as_ref().unwrap();
        assert!(doc.is_csr());
        assert!(doc.subject().contains("Test Certificate"));
    }

    #[test]
    fn test_load_csr_from_file() {
        let docs = load_documents_from_file(&std::path::PathBuf::from("assets/test.csr"));
        assert!(docs.is_ok());
        let docs = docs.unwrap();
        assert_eq!(docs.len(), 1);
        assert!(docs[0].is_csr());
    }

    #[test]
    fn test_convert_pem_to_der() {
        use std::path::PathBuf;

        let pem_path = PathBuf::from("assets/baidu.com.pem");
        if !pem_path.exists() {
            println!("Skipping: asset not found");
            return;
        }

        let out_path = std::env::temp_dir().join("cer_viewer_test_convert_baidu.der");
        let result = convert_certificate(&pem_path, &out_path, ConvertFormat::Der);
        assert!(result.is_ok(), "PEM→DER conversion failed: {result:?}");

        let der_bytes = std::fs::read(&out_path).expect("output not written");
        assert!(!der_bytes.is_empty());
        // Valid DER starts with SEQUENCE tag 0x30.
        assert_eq!(der_bytes[0], 0x30, "DER should start with SEQUENCE tag");

        // The DER should be parseable as a certificate.
        let cert = crate::cert::parse_der_certificate(&der_bytes);
        assert!(cert.is_ok(), "resulting DER should parse: {cert:?}");

        // Clean up.
        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn test_convert_der_to_pem() {
        use std::path::PathBuf;

        let pem_path = PathBuf::from("assets/baidu.com.pem");
        if !pem_path.exists() {
            println!("Skipping: asset not found");
            return;
        }

        // First convert PEM → DER, then DER → PEM.
        let der_path = std::env::temp_dir().join("cer_viewer_test_convert_roundtrip.der");
        let pem_out_path = std::env::temp_dir().join("cer_viewer_test_convert_roundtrip.pem");

        convert_certificate(&pem_path, &der_path, ConvertFormat::Der).unwrap();
        let result = convert_certificate(&der_path, &pem_out_path, ConvertFormat::Pem);
        assert!(result.is_ok(), "DER→PEM conversion failed: {result:?}");

        let pem_bytes = std::fs::read(&pem_out_path).expect("output not written");
        let pem_str = std::str::from_utf8(&pem_bytes).expect("PEM should be UTF-8");
        assert!(pem_str.contains("-----BEGIN CERTIFICATE-----"));
        assert!(pem_str.contains("-----END CERTIFICATE-----"));

        // Round-tripped certificate should parse.
        let cert = crate::cert::parse_pem_certificate(&pem_bytes);
        assert!(cert.is_ok(), "round-tripped PEM should parse: {cert:?}");

        // Clean up.
        let _ = std::fs::remove_file(&der_path);
        let _ = std::fs::remove_file(&pem_out_path);
    }

    #[test]
    fn test_convert_pem_already_pem_is_noop() {
        use std::path::PathBuf;

        let pem_path = PathBuf::from("assets/baidu.com.pem");
        if !pem_path.exists() {
            println!("Skipping: asset not found");
            return;
        }

        let out_path = std::env::temp_dir().join("cer_viewer_test_convert_noop.pem");
        let result = convert_certificate(&pem_path, &out_path, ConvertFormat::Pem);
        assert!(result.is_ok());

        let original = std::fs::read(&pem_path).unwrap();
        let output = std::fs::read(&out_path).unwrap();
        assert_eq!(
            original, output,
            "no-op conversion should produce identical bytes"
        );

        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn test_convert_nonexistent_input_returns_error() {
        use std::path::PathBuf;

        let result = convert_certificate(
            &PathBuf::from("/tmp/nonexistent_cert_12345.pem"),
            &PathBuf::from("/tmp/out.der"),
            ConvertFormat::Der,
        );
        assert!(result.is_err(), "expected error for missing file");
    }
}
