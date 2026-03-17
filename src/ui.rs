//! UI rendering for the certificate viewer.
//!
//! Contains the [`CertViewerApp`] struct that implements [`eframe::App`],
//! plus helpers for drawing the certificate field tree.

use crate::cert::{self, CertField, CertId, ParsedCert, ValidityStatus};
use crate::security::{is_potentially_sensitive, sensitive_copy_warning, SensitiveDataType};
use crate::theme;
use egui::{
    CollapsingHeader, Context, CornerRadius, Frame, Id, Key, KeyboardShortcut, Margin, RichText,
    ScrollArea, Stroke, Ui, Vec2,
};
use std::collections::HashMap;
use tracing::{info, warn};

// ── Keyboard shortcuts ──────────────────────────────────────────────

const OPEN_FILES_SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(egui::Modifiers::COMMAND, Key::O);
const CLOSE_TAB_SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(egui::Modifiers::COMMAND, Key::W);

// ── Tab action for deferred UI updates ──────────────────────────────

/// Deferred tab actions to avoid mutability issues during UI rendering.
#[derive(Clone, Copy)]
enum TabAction {
    /// Switch to the tab at the given index.
    Select(usize),
    /// Close the tab at the given index.
    Close(usize),
}

// ── Application state ──────────────────────────────────────────────

/// Main application state for the certificate viewer.
pub struct CertViewerApp {
    /// Currently loaded certificates (maintains insertion order).
    certs: Vec<ParsedCert>,
    /// Map from certificate ID to index for O(1) lookup.
    cert_index: HashMap<CertId, usize>,
    /// Index of the selected certificate tab.
    selected_tab: usize,
    /// Error messages to display (collected from all file operations).
    error_msgs: Vec<String>,
    /// Info message to display, if any.
    info_msg: Option<String>,
    /// Whether the theme has been applied.
    theme_applied: bool,
    /// Cached clipboard instance.
    clipboard: Option<arboard::Clipboard>,
}

impl CertViewerApp {
    /// Create a new application with no certificates loaded.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::setup_chinese_fonts(&cc.egui_ctx);

        let clipboard = match arboard::Clipboard::new() {
            Ok(cb) => Some(cb),
            Err(e) => {
                tracing::warn!("Failed to initialize clipboard: {}", e);
                None
            }
        };

        Self {
            certs: Vec::new(),
            cert_index: HashMap::new(),
            selected_tab: 0,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            clipboard,
        }
    }

    /// Setup Chinese font for rendering Chinese characters.
    fn setup_chinese_fonts(ctx: &egui::Context) {
        let mut fonts = egui::FontDefinitions::default();

        fonts.font_data.insert(
            "NotoSansSC".to_owned(),
            std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/NotoSansSC-Regular.ttf"
            ))),
        );

        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .push("NotoSansSC".to_owned());

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
                if let Some(existing_idx) = self.find_certificate_by_id(&parsed.id) {
                    info!(id = %parsed.id, "Certificate already loaded, switching to tab");
                    self.selected_tab = existing_idx;
                    self.show_info(format!(
                        "Certificate already loaded: {}",
                        parsed.display_name
                    ));
                    return false;
                }

                info!(name = %parsed.display_name, "Certificate loaded");
                self.error_msgs.clear();
                let idx = self.certs.len();
                self.cert_index.insert(parsed.id.clone(), idx);
                self.certs.push(parsed);
                self.selected_tab = idx;
                true
            }
            Err(e) => {
                warn!(error = %e, "Failed to load certificate");
                self.error_msgs.push(e.to_string());
                false
            }
        }
    }

    /// Find a certificate by its ID, returns the index if found.
    fn find_certificate_by_id(&self, id: &CertId) -> Option<usize> {
        self.cert_index.get(id).copied()
    }

    /// Load certificates from multiple files, supporting PEM certificate chains.
    fn load_files(&mut self, paths: Vec<std::path::PathBuf>) {
        let mut loaded_count = 0;
        let mut skipped_count = 0;
        let mut errors: Vec<String> = Vec::new();
        let mut last_loaded_idx: Option<usize> = None;

        for path in &paths {
            match std::fs::read(path) {
                Ok(data) => {
                    // Use parse_certificates to support multi-cert PEM chains
                    let results = cert::parse_certificates(&data);
                    for result in &results {
                        match result {
                            Ok(parsed) => {
                                if let Some(existing_idx) = self.find_certificate_by_id(&parsed.id)
                                {
                                    info!(
                                        id = %parsed.id,
                                        "Certificate already loaded from {:?}, skipping",
                                        path
                                    );
                                    last_loaded_idx = Some(existing_idx);
                                    skipped_count += 1;
                                } else {
                                    info!(name = %parsed.display_name, "Certificate loaded from {:?}", path);
                                    let idx = self.certs.len();
                                    self.cert_index.insert(parsed.id.clone(), idx);
                                    self.certs.push(parsed.clone());
                                    last_loaded_idx = Some(idx);
                                    loaded_count += 1;
                                }
                            }
                            Err(e) => {
                                let file_name = path
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("<invalid filename>");
                                errors.push(format!("Failed to parse {file_name}: {e}"));
                            }
                        }
                    }
                }
                Err(e) => {
                    let file_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<invalid filename>");
                    errors.push(format!("Failed to read {file_name}: {e}"));
                }
            }
        }

        // Switch to the last loaded or existing certificate
        if let Some(idx) = last_loaded_idx {
            self.selected_tab = idx;
            if loaded_count > 0 {
                self.error_msgs.clear();
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

        // Collect all errors
        self.error_msgs = errors;
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

            // Rebuild the index map since indices shifted
            self.rebuild_cert_index();

            self.show_info(format!("Closed: {}", name));
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
        self.cert_index.clear();
        self.selected_tab = 0;
        self.error_msgs.clear();
        self.show_info(format!("Cleared {} certificate(s)", count));
    }

    /// Rebuild the certificate index map after modifications.
    fn rebuild_cert_index(&mut self) {
        self.cert_index = self
            .certs
            .iter()
            .enumerate()
            .map(|(i, cert)| (cert.id.clone(), i))
            .collect();
    }

    /// Show an info message.
    fn show_info(&mut self, msg: String) {
        self.info_msg = Some(msg);
    }

    /// Copy text to clipboard using cached clipboard instance.
    ///
    /// This method checks if the text being copied contains sensitive data
    /// and logs a warning if it does.
    fn copy_to_clipboard(&mut self, text: String) {
        // Check for sensitive data before copying
        let data_type = SensitiveDataType::detect("clipboard", Some(&text));
        let is_sensitive = data_type.is_some();

        // Try cached instance first
        if let Some(clipboard) = &mut self.clipboard {
            match clipboard.set_text(&text) {
                Ok(()) => {
                    if is_sensitive {
                        let warning = sensitive_copy_warning(data_type.unwrap().description());
                        self.show_info(warning);
                        warn!(
                            "Copied sensitive data to clipboard: {} chars, type: {:?}",
                            text.len(),
                            data_type
                        );
                    } else {
                        self.show_info("Copied to clipboard".to_string());
                        info!("Copied to clipboard: {} chars", text.len());
                    }
                    return;
                }
                Err(e) => {
                    warn!("Failed to copy with cached clipboard: {}", e);
                }
            }
        }

        // Retry with fresh instance
        match arboard::Clipboard::new() {
            Ok(mut clipboard) => match clipboard.set_text(&text) {
                Ok(()) => {
                    self.clipboard = Some(clipboard);
                    if is_sensitive {
                        let warning = sensitive_copy_warning(data_type.unwrap().description());
                        self.show_info(warning);
                        warn!(
                            "Copied sensitive data to clipboard: {} chars, type: {:?}",
                            text.len(),
                            data_type
                        );
                    } else {
                        self.show_info("Copied to clipboard".to_string());
                        info!("Copied to clipboard: {} chars", text.len());
                    }
                }
                Err(e) => {
                    warn!("Failed to copy to clipboard: {}", e);
                    self.error_msgs.push(format!("Failed to copy: {}", e));
                }
            },
            Err(e) => {
                warn!("Failed to access clipboard: {}", e);
            }
        }
    }

    /// Handle keyboard shortcuts.
    fn handle_shortcuts(&mut self, ctx: &Context) {
        if ctx.input_mut(|i| i.consume_shortcut(&OPEN_FILES_SHORTCUT)) {
            self.open_file_dialog();
        }

        if ctx.input_mut(|i| i.consume_shortcut(&CLOSE_TAB_SHORTCUT)) && !self.certs.is_empty() {
            self.remove_certificate(self.selected_tab);
        }
    }

    /// Handle drag and drop (consumes events to prevent duplicate loading).
    fn handle_drag_drop(&mut self, ctx: &Context) {
        let paths: Vec<std::path::PathBuf> = ctx.input_mut(|i| {
            i.raw
                .dropped_files
                .drain(..)
                .filter_map(|f| f.path)
                .collect()
        });

        if !paths.is_empty() {
            self.load_files(paths);
        }
    }
}

impl eframe::App for CertViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            theme::apply_theme(ctx);
            self.theme_applied = true;
        }

        self.handle_shortcuts(ctx);
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

                    let btn =
                        egui::Button::new(RichText::new("Open Files...").size(theme::FONT_BODY))
                            .corner_radius(CornerRadius::same(4));
                    if ui.add(btn).clicked() {
                        self.open_file_dialog();
                    }

                    if !self.certs.is_empty() {
                        let clear_btn =
                            egui::Button::new(RichText::new("Clear All").size(theme::FONT_BODY))
                                .corner_radius(CornerRadius::same(4));
                        if ui.add(clear_btn).clicked() {
                            self.clear_all_certificates();
                        }
                    }

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

                                            let indicator_color = theme::validity_color(*validity);
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
                        .fill(theme::BANNER_INFO_BG)
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("[i]").color(theme::BANNER_INFO_TEXT));
                                ui.label(RichText::new(msg).color(theme::BANNER_INFO_VALUE));
                            });
                        });
                    ui.add_space(8.0);
                    self.info_msg = None;
                }

                // Error banners
                for msg in &self.error_msgs {
                    Frame::new()
                        .fill(theme::BANNER_ERROR_BG)
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!("[!] {msg}")).color(theme::BANNER_ERROR_TEXT),
                            );
                        });
                    ui.add_space(8.0);
                }

                if self.certs.is_empty() {
                    draw_empty_state(ui);
                } else if let Some(cert) = self.certs.get(self.selected_tab) {
                    let mut to_copy: Option<String> = None;
                    draw_certificate(ui, cert, &mut |text| {
                        to_copy = Some(text);
                    });

                    if let Some(text) = to_copy {
                        // Re-borrow self for clipboard
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

fn draw_certificate<F>(ui: &mut Ui, cert: &ParsedCert, on_copy: &mut F)
where
    F: FnMut(String),
{
    let status_text = theme::validity_text(cert.validity_status);
    let status_color = theme::validity_color(cert.validity_status);

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
                        on_copy(cert.to_pem());
                    }
                });
            });
        });

    ui.add_space(theme::SECTION_SPACING);

    ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for field in &cert.fields {
                draw_field(ui, field, 0, on_copy);
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
        let is_root = depth == 0;

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

                response.context_menu(|ui| {
                    let is_sensitive = is_potentially_sensitive(&field.label, Some(val));

                    if is_sensitive {
                        ui.label(
                            RichText::new("⚠️ Sensitive data")
                                .color(egui::Color32::YELLOW)
                                .italics(),
                        );
                        ui.separator();
                    }

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
            cert_index: HashMap::new(),
            selected_tab: 0,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            clipboard: None,
        };
        assert!(app.certs.is_empty());
        assert_eq!(app.selected_tab, 0);
        assert!(app.error_msgs.is_empty());
    }

    #[test]
    fn test_load_valid_certificate() {
        let mut app = CertViewerApp {
            certs: Vec::new(),
            cert_index: HashMap::new(),
            selected_tab: 0,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            clipboard: None,
        };
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);
        assert_eq!(app.certs.len(), 1);
        assert!(app.error_msgs.is_empty());
        assert_eq!(app.selected_tab, 0);
    }

    #[test]
    fn test_load_invalid_certificate_sets_error() {
        let mut app = CertViewerApp {
            certs: Vec::new(),
            cert_index: HashMap::new(),
            selected_tab: 0,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            clipboard: None,
        };
        app.load_certificate_bytes(b"not a certificate");
        assert!(app.certs.is_empty());
        assert!(!app.error_msgs.is_empty());
    }

    #[test]
    fn test_load_duplicate_certificate() {
        let mut app = CertViewerApp {
            certs: Vec::new(),
            cert_index: HashMap::new(),
            selected_tab: 0,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            clipboard: None,
        };
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);
        assert_eq!(app.certs.len(), 1);
        assert_eq!(app.selected_tab, 0);

        app.load_certificate_bytes(pem);
        assert_eq!(app.certs.len(), 1);
        assert_eq!(app.selected_tab, 0);
    }

    #[test]
    fn test_validity_status_display() {
        let mut app = CertViewerApp {
            certs: Vec::new(),
            cert_index: HashMap::new(),
            selected_tab: 0,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            clipboard: None,
        };
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);

        let cert = &app.certs[0];
        assert!(matches!(
            cert.validity_status,
            ValidityStatus::Valid | ValidityStatus::Expired | ValidityStatus::NotYetValid
        ));
    }
}
