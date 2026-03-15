//! cer-viewer — A modern X.509 certificate viewer built with egui/eframe.
//!
//! Supports PEM and DER encoded certificates with a collapsible field tree,
//! dark theme, and file-open dialog.

mod cert;
mod theme;
mod ui;

use tracing::info;

fn main() -> eframe::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
        .init();

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
