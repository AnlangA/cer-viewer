//! cer-viewer — A modern X.509 certificate viewer built with egui/eframe.
//!
//! Supports PEM and DER encoded certificates with a collapsible field tree,
//! dark theme, and file-open dialog.

mod cert;
mod cli;
mod theme;
mod ui;

// New modular structure
mod export;
mod formats;
mod security;
mod utils;
mod validation;

use tracing::info;

fn main() -> eframe::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

    // Check if CLI mode is requested
    match cli::run() {
        Ok(true) => {
            // CLI mode was executed, exit
            return Ok(());
        }
        Ok(false) => {
            // No CLI args, continue to GUI
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }

    info!("Starting cer-viewer");

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 700.0])
            .with_min_inner_size([600.0, 400.0])
            .with_title("Certificate Viewer"),
        ..Default::default()
    };

    eframe::run_native(
        "cer-viewer",
        native_options,
        Box::new(|cc| {
            let app = ui::CertViewerApp::new(cc);
            Ok(Box::new(app))
        }),
    )
}
