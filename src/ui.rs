//! UI rendering for the certificate viewer.
//!
//! Contains the [`CertViewerApp`] struct that implements [`eframe::App`],
//! plus helpers for drawing the certificate field tree.

use crate::cert::{self, CertField, ParsedCert, ValidityStatus};
use crate::theme;
use egui::{
    CollapsingHeader, Context, CornerRadius, Frame, Id, Key, KeyboardShortcut, Margin, RichText,
    ScrollArea, Stroke, Ui, Vec2,
};
use tracing::{info, warn};

// ── Keyboard shortcuts ──────────────────────────────────────────────

const OPEN_FILES_SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(egui::Modifiers::COMMAND, Key::O);
const CLOSE_TAB_SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(egui::Modifiers::COMMAND, Key::W);

// ── Tab action for deferred UI updates ──────────────────────────────

#[derive(Clone, Copy)]
enum TabAction {
    Select(usize),
    Close(usize),
}

// ── Application state ──────────────────────────────────────────────

/// Main application state for the certificate viewer.
pub struct CertViewerApp {
    /// Currently loaded certificates.
    certs: Vec<ParsedCert>,
    /// Index of the selected certificate tab.
    selected_tab: usize,
    /// Error message to display, if any.
    error_msg: Option<String>,
    /// Info message to display, if any.
    info_msg: Option<String>,
    /// Whether the theme has been applied.
    theme_applied: bool,
}

impl CertViewerApp {
    /// Create a new application with no certificates loaded.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Configure Chinese font support
        Self::setup_chinese_fonts(&cc.egui_ctx);

        Self {
            certs: Vec::new(),
            selected_tab: 0,
            error_msg: None,
            info_msg: None,
            theme_applied: false,
        }
    }

    /// Setup Chinese font for rendering Chinese characters.
    fn setup_chinese_fonts(ctx: &egui::Context) {
        let mut fonts = egui::FontDefinitions::default();

        // Load the Chinese font (use from_static for compile-time included bytes)
        fonts.font_data.insert(
            "NotoSansSC".to_owned(),
            std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/NotoSansSC-Regular.ttf"
            ))),
        );

        // Add Chinese font to the proportional font family (used for body text)
        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .push("NotoSansSC".to_owned());

        // Add Chinese font to the monospace font family as well
        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .push("NotoSansSC".to_owned());

        ctx.set_fonts(fonts);
    }

    /// Load a certificate from raw bytes (auto-detects PEM/DER).
    /// Returns true if the certificate was loaded, false if it already existed.
    #[allow(dead_code)]
    pub fn load_certificate_bytes(&mut self, data: &[u8]) -> bool {
        match cert::parse_certificate(data) {
            Ok(parsed) => {
                // Check if certificate already exists
                if let Some(existing_idx) = self.find_certificate_by_serial(&parsed.serial_number) {
                    info!(serial = %parsed.serial_number, "Certificate already loaded, switching to tab");
                    self.selected_tab = existing_idx;
                    self.show_info(format!(
                        "Certificate already loaded: {}",
                        parsed.display_name
                    ));
                    return false;
                }

                info!(name = %parsed.display_name, "Certificate loaded");
                self.error_msg = None;
                self.certs.push(parsed);
                self.selected_tab = self.certs.len() - 1;
                true
            }
            Err(e) => {
                warn!(error = %e, "Failed to load certificate");
                self.error_msg = Some(e.to_string());
                false
            }
        }
    }

    /// Find a certificate by its serial number, returns the index if found.
    fn find_certificate_by_serial(&self, serial: &str) -> Option<usize> {
        self.certs
            .iter()
            .position(|cert| cert.serial_number == serial)
    }

    /// Load certificates from multiple files.
    fn load_files(&mut self, paths: Vec<std::path::PathBuf>) {
        let mut loaded_count = 0;
        let mut skipped_count = 0;
        let mut last_error: Option<String> = None;
        let mut last_loaded_idx: Option<usize> = None;

        for path in paths {
            match std::fs::read(&path) {
                Ok(data) => {
                    match cert::parse_certificate(&data) {
                        Ok(parsed) => {
                            // Check if certificate already exists
                            if let Some(existing_idx) =
                                self.find_certificate_by_serial(&parsed.serial_number)
                            {
                                info!(
                                    serial = %parsed.serial_number,
                                    "Certificate already loaded from {:?}, skipping",
                                    path
                                );
                                last_loaded_idx = Some(existing_idx);
                                skipped_count += 1;
                            } else {
                                info!(name = %parsed.display_name, "Certificate loaded from {:?}", path);
                                self.certs.push(parsed);
                                last_loaded_idx = Some(self.certs.len() - 1);
                                loaded_count += 1;
                            }
                        }
                        Err(e) => {
                            last_error = Some(format!(
                                "Failed to parse {:?}: {}",
                                path.file_name().unwrap_or_default(),
                                e
                            ));
                        }
                    }
                }
                Err(e) => {
                    last_error = Some(format!(
                        "Failed to read {:?}: {e}",
                        path.file_name().unwrap_or_default()
                    ));
                }
            }
        }

        // Switch to the last loaded or existing certificate
        if let Some(idx) = last_loaded_idx {
            self.selected_tab = idx;
            if loaded_count > 0 {
                self.error_msg = None;
            }
        }

        // Show info about results
        if loaded_count > 0 || skipped_count > 0 {
            let mut msg = String::new();
            if loaded_count > 0 {
                msg.push_str(&format!("Loaded {} certificate(s)", loaded_count));
            }
            if skipped_count > 0 {
                if !msg.is_empty() {
                    msg.push_str(", ");
                }
                msg.push_str(&format!("skipped {} duplicate(s)", skipped_count));
            }
            self.show_info(msg);
        }

        if let Some(e) = last_error {
            self.error_msg = Some(e);
        }
    }

    /// Open a file dialog and load the selected certificates (supports multiple selection).
    fn open_file_dialog(&mut self) {
        let files = rfd::FileDialog::new()
            .set_title("Open Certificates")
            .add_filter("Certificates", &["pem", "crt", "cer", "der", "cert"])
            .add_filter("All Files", &["*"])
            .pick_files();

        if let Some(paths) = files {
            self.load_files(paths);
        }
    }

    /// Remove a certificate at the given index.
    fn remove_certificate(&mut self, index: usize) {
        if index < self.certs.len() {
            let name = self.certs[index].display_name.clone();
            self.certs.remove(index);
            self.show_info(format!("Closed: {}", name));
            // Adjust selected tab
            if self.certs.is_empty() {
                self.selected_tab = 0;
            } else if self.selected_tab >= self.certs.len() {
                self.selected_tab = self.certs.len() - 1;
            } else if self.selected_tab > index {
                self.selected_tab -= 1;
            }
        }
    }

    /// Clear all loaded certificates.
    fn clear_all_certificates(&mut self) {
        let count = self.certs.len();
        self.certs.clear();
        self.selected_tab = 0;
        self.error_msg = None;
        self.show_info(format!("Cleared {} certificate(s)", count));
    }

    /// Show an info message.
    fn show_info(&mut self, msg: String) {
        self.info_msg = Some(msg);
    }

    /// Copy text to clipboard.
    fn copy_to_clipboard(&mut self, text: String) {
        match arboard::Clipboard::new() {
            Ok(mut clipboard) => match clipboard.set_text(&text) {
                Ok(()) => {
                    self.show_info("Copied to clipboard".to_string());
                    info!("Copied to clipboard: {} chars", text.len());
                }
                Err(e) => {
                    warn!("Failed to copy to clipboard: {}", e);
                    self.error_msg = Some(format!("Failed to copy: {}", e));
                }
            },
            Err(e) => {
                warn!("Failed to access clipboard: {}", e);
            }
        }
    }

    /// Handle keyboard shortcuts.
    fn handle_shortcuts(&mut self, ctx: &Context) {
        // Ctrl+O: Open files
        if ctx.input_mut(|i| i.consume_shortcut(&OPEN_FILES_SHORTCUT)) {
            self.open_file_dialog();
        }

        // Ctrl+W: Close current tab
        if ctx.input_mut(|i| i.consume_shortcut(&CLOSE_TAB_SHORTCUT)) && !self.certs.is_empty() {
            self.remove_certificate(self.selected_tab);
        }
    }

    /// Handle drag and drop.
    fn handle_drag_drop(&mut self, ctx: &Context) {
        // Check for dropped files
        let dropped_files = ctx.input(|i| i.raw.dropped_files.clone());

        if !dropped_files.is_empty() {
            let paths: Vec<std::path::PathBuf> =
                dropped_files.into_iter().filter_map(|f| f.path).collect();

            if !paths.is_empty() {
                self.load_files(paths);
            }
        }
    }
}

impl eframe::App for CertViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            theme::apply_theme(ctx);
            self.theme_applied = true;
        }

        // Handle keyboard shortcuts
        self.handle_shortcuts(ctx);

        // Handle drag and drop
        self.handle_drag_drop(ctx);

        // ── Top panel: toolbar ─────────────────────────────────
        egui::TopBottomPanel::top("toolbar")
            .frame(
                Frame::new()
                    .fill(theme::BG_HEADER)
                    .inner_margin(Margin::symmetric(12, 8))
                    .stroke(Stroke::new(1.0, theme::BORDER)),
            )
            .show(ctx, |ui| {
                // Menu bar
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Certificate Viewer")
                            .size(theme::FONT_TITLE)
                            .color(theme::ACCENT)
                            .strong(),
                    );

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);

                    // Quick action buttons
                    let btn =
                        egui::Button::new(RichText::new("Open Files...").size(theme::FONT_BODY))
                            .corner_radius(CornerRadius::same(4));
                    if ui.add(btn).clicked() {
                        self.open_file_dialog();
                    }

                    // Clear all button
                    if !self.certs.is_empty() {
                        let clear_btn =
                            egui::Button::new(RichText::new("Clear All").size(theme::FONT_BODY))
                                .corner_radius(CornerRadius::same(4));
                        if ui.add(clear_btn).clicked() {
                            self.clear_all_certificates();
                        }
                    }

                    // Keyboard shortcut hints
                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Ctrl+O: Open | Ctrl+W: Close")
                            .size(11.0)
                            .color(theme::TEXT_SECONDARY),
                    );
                });

                // Tab bar for certificates (show when at least 1 cert)
                if !self.certs.is_empty() {
                    ui.add_space(4.0);

                    // Collect tab data to avoid borrow issues
                    let tab_data: Vec<(usize, String, bool, ValidityStatus)> = self
                        .certs
                        .iter()
                        .enumerate()
                        .map(|(i, cert)| {
                            let label = if cert.display_name.len() > 20 {
                                format!("{}...", &cert.display_name[..17])
                            } else {
                                cert.display_name.clone()
                            };
                            (i, label, i == self.selected_tab, cert.validity_status)
                        })
                        .collect();

                    let mut action: Option<TabAction> = None;

                    egui::ScrollArea::horizontal()
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                for (i, label, is_selected, validity) in &tab_data {
                                    let tab_frame = Frame::new()
                                        .fill(if *is_selected {
                                            theme::BG_SECONDARY
                                        } else {
                                            egui::Color32::TRANSPARENT
                                        })
                                        .corner_radius(CornerRadius::same(4))
                                        .inner_margin(Margin::symmetric(8, 4))
                                        .stroke(if *is_selected {
                                            Stroke::new(1.0, theme::ACCENT)
                                        } else {
                                            Stroke::new(1.0, theme::BORDER)
                                        });

                                    tab_frame.show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing = Vec2::new(6.0, 0.0);

                                            // Validity indicator
                                            let indicator_color = match validity {
                                                ValidityStatus::Valid => {
                                                    egui::Color32::from_rgb(80, 200, 120)
                                                }
                                                ValidityStatus::NotYetValid => {
                                                    egui::Color32::from_rgb(255, 200, 80)
                                                }
                                                ValidityStatus::Expired => {
                                                    egui::Color32::from_rgb(255, 100, 100)
                                                }
                                            };
                                            ui.label(RichText::new("*").color(indicator_color));

                                            let text = RichText::new(label)
                                                .size(theme::FONT_BODY)
                                                .color(if *is_selected {
                                                    theme::TEXT_PRIMARY
                                                } else {
                                                    theme::TEXT_SECONDARY
                                                });

                                            if ui.selectable_label(*is_selected, text).clicked() {
                                                action = Some(TabAction::Select(*i));
                                            }

                                            let close_btn =
                                                egui::Button::new(RichText::new("x").size(11.0))
                                                    .fill(egui::Color32::TRANSPARENT)
                                                    .corner_radius(CornerRadius::same(2));

                                            if ui.add(close_btn).clicked() {
                                                action = Some(TabAction::Close(*i));
                                            }
                                        });
                                    });

                                    ui.add_space(2.0);
                                }
                            });
                        });

                    // Apply action after rendering
                    if let Some(act) = action {
                        match act {
                            TabAction::Select(i) => self.selected_tab = i,
                            TabAction::Close(i) => self.remove_certificate(i),
                        }
                    }
                }
            });

        // ── Central panel: certificate content ─────────────────
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(theme::BG_PRIMARY)
                    .inner_margin(Margin::same(16)),
            )
            .show(ctx, |ui| {
                // Info banner
                if let Some(ref msg) = self.info_msg {
                    Frame::new()
                        .fill(egui::Color32::from_rgb(30, 80, 50))
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new("[i]")
                                        .color(egui::Color32::from_rgb(120, 255, 180)),
                                );
                                ui.label(
                                    RichText::new(msg)
                                        .color(egui::Color32::from_rgb(200, 255, 220)),
                                );
                            });
                        });
                    ui.add_space(8.0);
                    // Auto-clear info message
                    self.info_msg = None;
                }

                // Error banner
                if let Some(ref msg) = self.error_msg {
                    Frame::new()
                        .fill(egui::Color32::from_rgb(80, 30, 30))
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!("[!] {msg}"))
                                    .color(egui::Color32::from_rgb(255, 120, 120)),
                            );
                        });
                    ui.add_space(8.0);
                }

                if self.certs.is_empty() {
                    draw_empty_state(ui);
                } else if let Some(cert) = self.certs.get(self.selected_tab) {
                    // Clone needed data to avoid borrow issues
                    let cert_clone = cert.clone();
                    let mut to_copy: Option<String> = None;
                    draw_certificate(ui, &cert_clone, |text| {
                        to_copy = Some(text);
                    });

                    // Apply copy after drawing
                    if let Some(text) = to_copy {
                        self.copy_to_clipboard(text);
                    }
                }
            });
    }
}

// ── Empty state ────────────────────────────────────────────────────

fn draw_empty_state(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(80.0);
        ui.label(
            RichText::new("No certificate loaded")
                .size(22.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(12.0);
        ui.label(
            RichText::new("Click \"Open Files...\" or drag & drop certificates here")
                .size(14.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("Supported formats: PEM, DER, CRT, CER")
                .size(12.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(20.0);
        ui.label(
            RichText::new("Keyboard shortcuts:")
                .size(12.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("Ctrl+O: Open files  |  Ctrl+W: Close tab")
                .size(11.0)
                .color(theme::TEXT_SECONDARY),
        );
    });
}

// ── Certificate rendering ──────────────────────────────────────────

fn draw_certificate<F>(ui: &mut Ui, cert: &ParsedCert, mut on_copy: F)
where
    F: FnMut(String),
{
    // Header card with validity status
    let (status_text, status_color) = match cert.validity_status {
        ValidityStatus::Valid => ("[OK] Valid", egui::Color32::from_rgb(80, 200, 120)),
        ValidityStatus::NotYetValid => ("[!] Not Yet Valid", egui::Color32::from_rgb(255, 200, 80)),
        ValidityStatus::Expired => ("[X] Expired", egui::Color32::from_rgb(255, 100, 100)),
    };

    Frame::new()
        .fill(theme::BG_SECONDARY)
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, theme::BORDER))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&cert.display_name)
                            .size(theme::FONT_TITLE)
                            .color(theme::TEXT_PRIMARY)
                            .strong(),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(status_text)
                            .size(theme::FONT_BODY)
                            .color(status_color),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(&cert.not_before)
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_SECONDARY),
                    );
                    ui.label(
                        RichText::new(" -> ")
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_SECONDARY),
                    );
                    ui.label(
                        RichText::new(&cert.not_after)
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_SECONDARY),
                    );
                });
                ui.add_space(4.0);

                // Quick actions
                ui.horizontal(|ui| {
                    let copy_btn =
                        egui::Button::new(RichText::new("Copy PEM").size(theme::FONT_BODY))
                            .corner_radius(CornerRadius::same(4));
                    if ui.add(copy_btn).clicked() {
                        // Generate a PEM representation (simplified)
                        let pem_data = format!(
                            "Subject: {}\nIssuer: {}\nSerial: {}\nValid: {} - {}\nSHA-256: {}",
                            cert.subject,
                            cert.issuer,
                            cert.serial_number,
                            cert.not_before,
                            cert.not_after,
                            cert.sha256_fingerprint
                        );
                        on_copy(pem_data);
                    }
                });
            });
        });

    ui.add_space(theme::SECTION_SPACING);

    // Scrollable field tree
    ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for field in &cert.fields {
                draw_field(ui, field, 0, &mut on_copy);
            }
        });
}

fn draw_field<F>(ui: &mut Ui, field: &CertField, depth: usize, on_copy: &mut F)
where
    F: FnMut(String),
{
    let id = Id::new(&field.label)
        .with(depth)
        .with(field.value.as_deref().unwrap_or("").get(..20).unwrap_or(""));

    if field.has_children() {
        // Collapsible container
        let is_root = depth == 0;

        // Add "Fingerprints" prefix
        let prefix = if depth == 0 {
            match field.label.as_str() {
                "Version" => "[V]",
                "Serial Number" => "[#]",
                "Signature Algorithm" | "Signature Value" => "[S]",
                "Issuer" => "[I]",
                "Subject" => "[S]",
                "Validity" => "[T]",
                "Subject Public Key Info" => "[K]",
                "Extensions" => "[X]",
                "Fingerprints" => "[F]",
                _ => "[*]",
            }
        } else {
            ">"
        };

        Frame::new()
            .fill(if is_root {
                theme::BG_SECONDARY
            } else {
                egui::Color32::TRANSPARENT
            })
            .corner_radius(CornerRadius::same(if is_root { 4 } else { 0 }))
            .inner_margin(if is_root {
                Margin::same(6)
            } else {
                Margin::same(1)
            })
            .stroke(if is_root {
                Stroke::new(1.0, theme::BORDER)
            } else {
                Stroke::NONE
            })
            .show(ui, |ui| {
                let header = RichText::new(format!("{prefix} {}", field.label))
                    .size(if depth == 0 {
                        theme::FONT_HEADING
                    } else {
                        theme::FONT_BODY
                    })
                    .color(if depth == 0 {
                        theme::TEXT_PRIMARY
                    } else {
                        theme::TEXT_LABEL
                    })
                    .strong();

                CollapsingHeader::new(header)
                    .id_salt(id)
                    .default_open(is_root && !field.label.contains("Signature Value"))
                    .show(ui, |ui| {
                        // Summary value (e.g. Issuer DN string)
                        if let Some(ref val) = field.value {
                            ui.horizontal_wrapped(|ui| {
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(val)
                                        .font(theme::mono_font())
                                        .color(theme::TEXT_VALUE),
                                );
                            });
                            ui.add_space(2.0);
                        }
                        for child in &field.children {
                            draw_field(ui, child, depth + 1, on_copy);
                        }
                    });
            });

        if is_root {
            ui.add_space(4.0);
        }
    } else {
        // Leaf: label -> value with context menu for copying
        ui.horizontal_wrapped(|ui| {
            ui.add_space(4.0);
            ui.label(
                RichText::new(&field.label)
                    .font(theme::body_font())
                    .color(theme::TEXT_LABEL),
            );
            if let Some(ref val) = field.value {
                ui.label(
                    RichText::new(" : ")
                        .color(theme::TEXT_SECONDARY)
                        .size(theme::FONT_BODY),
                );
                let is_hex_like = val.contains(':') && val.len() > 40;
                let response = ui.label(
                    RichText::new(val)
                        .font(if is_hex_like {
                            theme::mono_font()
                        } else {
                            theme::body_font()
                        })
                        .color(theme::TEXT_VALUE),
                );

                // Context menu for copying
                response.context_menu(|ui| {
                    if ui.button("Copy value").clicked() {
                        on_copy(val.clone());
                        ui.close();
                    }
                    if ui.button("Copy label: value").clicked() {
                        on_copy(format!("{}: {}", field.label, val));
                        ui.close();
                    }
                });
            }
        });
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_initial_state() {
        let app = CertViewerApp {
            certs: Vec::new(),
            selected_tab: 0,
            error_msg: None,
            info_msg: None,
            theme_applied: false,
        };
        assert!(app.certs.is_empty());
        assert_eq!(app.selected_tab, 0);
        assert!(app.error_msg.is_none());
    }

    #[test]
    fn test_load_valid_certificate() {
        let mut app = CertViewerApp {
            certs: Vec::new(),
            selected_tab: 0,
            error_msg: None,
            info_msg: None,
            theme_applied: false,
        };
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);
        assert_eq!(app.certs.len(), 1);
        assert!(app.error_msg.is_none());
        assert_eq!(app.selected_tab, 0);
    }

    #[test]
    fn test_load_invalid_certificate_sets_error() {
        let mut app = CertViewerApp {
            certs: Vec::new(),
            selected_tab: 0,
            error_msg: None,
            info_msg: None,
            theme_applied: false,
        };
        app.load_certificate_bytes(b"not a certificate");
        assert!(app.certs.is_empty());
        assert!(app.error_msg.is_some());
    }

    #[test]
    fn test_load_duplicate_certificate() {
        // Loading the same certificate twice should only keep one copy
        let mut app = CertViewerApp {
            certs: Vec::new(),
            selected_tab: 0,
            error_msg: None,
            info_msg: None,
            theme_applied: false,
        };
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);
        assert_eq!(app.certs.len(), 1);
        assert_eq!(app.selected_tab, 0);

        // Load the same certificate again - should not add a duplicate
        app.load_certificate_bytes(pem);
        assert_eq!(app.certs.len(), 1); // Still only 1 certificate
        assert_eq!(app.selected_tab, 0); // Tab stays at 0
    }

    #[test]
    fn test_validity_status_display() {
        let mut app = CertViewerApp {
            certs: Vec::new(),
            selected_tab: 0,
            error_msg: None,
            info_msg: None,
            theme_applied: false,
        };
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);

        // Check that validity status is set
        let cert = &app.certs[0];
        assert!(matches!(
            cert.validity_status,
            ValidityStatus::Valid | ValidityStatus::Expired | ValidityStatus::NotYetValid
        ));
    }
}
