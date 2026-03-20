//! cer-viewer — A modern X.509 certificate viewer built with egui/eframe.
//!
//! Supports PEM and DER encoded certificates with a collapsible field tree,
//! dark theme, and file-open dialog.

// On Windows release builds, hide the console window so the GUI launches
// without an accompanying terminal.  When the binary is invoked with CLI
// arguments we re-attach to the parent console (see `try_attach_parent_console`)
// so that command-line output still reaches the calling terminal.
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod cert;
mod cli;
mod config;
mod document;
mod generation;
mod theme;
mod ui;

// New modular structure
mod export;
mod formats;
mod security;
mod utils;
mod validation;

use tracing::info;

/// On Windows release builds the binary is compiled with
/// `windows_subsystem = "windows"`, which prevents an unwanted console window
/// from appearing when the GUI is launched by double-clicking.  However this
/// also detaches stdout/stderr from the parent process, so CLI output would be
/// silently lost.
///
/// This function re-attaches to the **parent** console when the binary is
/// invoked with at least one command-line argument (i.e. CLI mode).  It is a
/// no-op on non-Windows platforms and in debug builds (where the console is
/// always present).
#[cfg(all(windows, not(debug_assertions)))]
fn try_attach_parent_console() {
    // Attaches the calling process to the console of the parent process.
    // Returns non-zero on success; failures are intentionally ignored
    // (e.g. when there is no parent console because the user double-clicked
    // the binary).
    const ATTACH_PARENT_PROCESS: u32 = 0xFFFF_FFFF;
    extern "system" {
        fn AttachConsole(dwProcessId: u32) -> i32;
    }
    let _ = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) };
}

fn main() -> eframe::Result<()> {
    // Re-attach to the parent console on Windows release builds when any
    // CLI arguments are present, so that command output remains visible.
    #[cfg(all(windows, not(debug_assertions)))]
    if std::env::args().count() > 1 {
        try_attach_parent_console();
    }

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

    let config = config::Config::load();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([config.window_width, config.window_height])
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
