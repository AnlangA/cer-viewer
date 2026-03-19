//! Certificate generation dialog UI.
//!
//! Provides egui-based dialogs for generating self-signed certificates and CSRs.

#![allow(dead_code)] // Module is not yet wired into the main app

use crate::generation::csr_gen::{generate_csr, CsrParams};
use crate::generation::self_signed::{generate_self_signed_cert, KeyType, SelfSignedParams};
use crate::theme;
use egui::{CornerRadius, RichText};

/// Generation mode for the dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerationMode {
    /// Generate a self-signed certificate.
    SelfSigned,
    /// Generate a Certificate Signing Request.
    Csr,
}

/// State for the certificate generation dialog.
pub(crate) struct GenerateDialog {
    /// Whether the dialog is visible.
    visible: bool,
    /// Current generation mode.
    mode: GenerationMode,
    /// Common Name input.
    cn: String,
    /// Validity days input (for self-signed certs).
    validity_days: String,
    /// Key type selection.
    key_type: KeyType,
    /// Key size input.
    key_size: String,
    /// SAN entries (one per line).
    sans_text: String,
    /// Whether to generate as CA (self-signed only).
    is_ca: bool,
    /// Result message to display.
    result_msg: Option<String>,
    /// Error message to display.
    error_msg: Option<String>,
}

impl GenerateDialog {
    /// Create a new generation dialog.
    pub(crate) fn new() -> Self {
        Self {
            visible: false,
            mode: GenerationMode::SelfSigned,
            cn: String::new(),
            validity_days: "365".to_string(),
            key_type: KeyType::Rsa,
            key_size: "2048".to_string(),
            sans_text: String::new(),
            is_ca: false,
            result_msg: None,
            error_msg: None,
        }
    }

    /// Show the dialog with the specified mode.
    pub(crate) fn show(&mut self, mode: GenerationMode) {
        self.visible = true;
        self.mode = mode;
        self.result_msg = None;
        self.error_msg = None;
    }

    /// Hide the dialog.
    pub(crate) fn hide(&mut self) {
        self.visible = false;
    }

    /// Check if the dialog is currently visible.
    pub(crate) fn is_visible(&self) -> bool {
        self.visible
    }

    /// Draw the generation dialog. Returns `true` if a certificate/CSR was generated.
    pub(crate) fn draw(&mut self, ui: &mut egui::Ui) -> Option<GenerationResult> {
        if !self.visible {
            return None;
        }

        let mut generated = None;

        let area = egui::Area::new(egui::Id::new("generate_dialog_area"))
            .fixed_pos(ui.available_rect_before_wrap().center())
            .order(egui::Order::Foreground);

        area.show(ui.ctx(), |ui| {
            let frame = egui::Frame::new()
                .fill(theme::BG_SECONDARY)
                .inner_margin(egui::Margin::same(20))
                .corner_radius(CornerRadius::same(8))
                .stroke((1.0, theme::BORDER));

            frame.show(ui, |ui| {
                ui.set_width(420.0);
                ui.vertical_centered(|ui| {
                    // Title
                    let title = match self.mode {
                        GenerationMode::SelfSigned => "Generate Self-Signed Certificate",
                        GenerationMode::Csr => "Generate Certificate Signing Request",
                    };
                    ui.label(
                        RichText::new(title)
                            .size(theme::FONT_HEADING)
                            .color(theme::TEXT_PRIMARY),
                    );
                    ui.add_space(12.0);

                    // Common Name
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Common Name (CN):")
                                .size(theme::FONT_BODY)
                                .color(theme::TEXT_LABEL),
                        );
                        ui.add(egui::TextEdit::singleline(&mut self.cn).desired_width(280.0));
                    });
                    ui.add_space(6.0);

                    // Validity Days (only for self-signed)
                    if self.mode == GenerationMode::SelfSigned {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new("Validity (days):")
                                    .size(theme::FONT_BODY)
                                    .color(theme::TEXT_LABEL),
                            );
                            ui.add(
                                egui::TextEdit::singleline(&mut self.validity_days)
                                    .desired_width(100.0),
                            );
                        });
                        ui.add_space(6.0);

                        // CA checkbox
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut self.is_ca, "Certificate Authority (CA)");
                        });
                        ui.add_space(6.0);
                    }

                    // Key Type
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Key Type:")
                                .size(theme::FONT_BODY)
                                .color(theme::TEXT_LABEL),
                        );
                        let rsa_selected = self.key_type == KeyType::Rsa;
                        if ui.selectable_label(rsa_selected, "RSA").clicked() {
                            self.key_type = KeyType::Rsa;
                            self.key_size = self.key_type.default_key_size().to_string();
                        }
                        if ui.selectable_label(!rsa_selected, "EC").clicked() {
                            self.key_type = KeyType::Ec;
                            self.key_size = self.key_type.default_key_size().to_string();
                        }
                    });
                    ui.add_space(6.0);

                    // Key Size
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("Key Size:")
                                .size(theme::FONT_BODY)
                                .color(theme::TEXT_LABEL),
                        );
                        ui.add(egui::TextEdit::singleline(&mut self.key_size).desired_width(100.0));
                    });
                    ui.add_space(6.0);

                    // SANs
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new("SANs (one per line):")
                                .size(theme::FONT_BODY)
                                .color(theme::TEXT_LABEL),
                        );
                    });
                    ui.add(
                        egui::TextEdit::multiline(&mut self.sans_text)
                            .desired_rows(3)
                            .desired_width(380.0),
                    );
                    ui.add_space(12.0);

                    // Result / Error messages
                    if let Some(ref msg) = self.result_msg {
                        ui.label(
                            RichText::new(msg)
                                .size(theme::FONT_MONO)
                                .color(theme::STATUS_VALID),
                        );
                    }
                    if let Some(ref msg) = self.error_msg {
                        ui.label(
                            RichText::new(msg)
                                .size(theme::FONT_MONO)
                                .color(theme::STATUS_NOT_YET_VALID),
                        );
                    }
                    ui.add_space(8.0);

                    // Buttons
                    ui.horizontal(|ui| {
                        ui.add_space(80.0);
                        if ui
                            .add(
                                egui::Button::new(RichText::new("Cancel").size(theme::FONT_BODY))
                                    .corner_radius(CornerRadius::same(4))
                                    .fill(theme::BG_HOVER),
                            )
                            .clicked()
                        {
                            self.hide();
                        }

                        ui.add_space(8.0);

                        if ui
                            .add(
                                egui::Button::new(RichText::new("Generate").size(theme::FONT_BODY))
                                    .corner_radius(CornerRadius::same(4))
                                    .fill(theme::ACCENT),
                            )
                            .clicked()
                        {
                            generated = self.do_generate();
                        }
                    });
                    ui.add_space(8.0);
                });
            });
        });

        generated
    }

    fn do_generate(&mut self) -> Option<GenerationResult> {
        // Validate inputs
        if self.cn.trim().is_empty() {
            self.error_msg = Some("Common Name cannot be empty.".to_string());
            self.result_msg = None;
            return None;
        }

        let key_size: u32 = match self.key_size.trim().parse() {
            Ok(v) => v,
            Err(_) => {
                self.error_msg = Some("Invalid key size.".to_string());
                self.result_msg = None;
                return None;
            }
        };

        let sans: Vec<String> = self
            .sans_text
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();

        match self.mode {
            GenerationMode::SelfSigned => {
                let validity_days: u32 = match self.validity_days.trim().parse() {
                    Ok(v) if v > 0 => v,
                    _ => {
                        self.error_msg =
                            Some("Validity days must be a positive integer.".to_string());
                        self.result_msg = None;
                        return None;
                    }
                };

                let params = SelfSignedParams {
                    cn: self.cn.trim().to_string(),
                    validity_days,
                    key_type: self.key_type,
                    key_size,
                    sans,
                    is_ca: self.is_ca,
                };

                match generate_self_signed_cert(&params) {
                    Ok(cert) => {
                        self.result_msg = Some("Certificate generated successfully.".to_string());
                        self.error_msg = None;
                        Some(GenerationResult::SelfSigned {
                            pem: cert.pem,
                            der: cert.der,
                        })
                    }
                    Err(e) => {
                        self.error_msg = Some(format!("Error: {e}"));
                        self.result_msg = None;
                        None
                    }
                }
            }
            GenerationMode::Csr => {
                let params = CsrParams {
                    cn: self.cn.trim().to_string(),
                    sans,
                    key_type: self.key_type,
                    key_size,
                };

                match generate_csr(&params) {
                    Ok(csr) => {
                        self.result_msg = Some("CSR generated successfully.".to_string());
                        self.error_msg = None;
                        Some(GenerationResult::Csr {
                            pem: csr.pem,
                            der: csr.der,
                        })
                    }
                    Err(e) => {
                        self.error_msg = Some(format!("Error: {e}"));
                        self.result_msg = None;
                        None
                    }
                }
            }
        }
    }
}

impl Default for GenerateDialog {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of a generation operation.
pub(crate) enum GenerationResult {
    /// A self-signed certificate was generated.
    SelfSigned {
        /// Certificate in PEM format.
        pem: String,
        /// Certificate in DER format.
        der: Vec<u8>,
    },
    /// A CSR was generated.
    Csr {
        /// CSR in PEM format.
        pem: String,
        /// CSR in DER format.
        der: Vec<u8>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialog_initial_state() {
        let dialog = GenerateDialog::new();
        assert!(!dialog.is_visible());
        assert!(dialog.cn.is_empty());
    }

    #[test]
    fn test_dialog_show_hide() {
        let mut dialog = GenerateDialog::new();
        dialog.show(GenerationMode::SelfSigned);
        assert!(dialog.is_visible());
        dialog.hide();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_dialog_default() {
        let dialog = GenerateDialog::default();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_generation_mode_eq() {
        assert_eq!(GenerationMode::SelfSigned, GenerationMode::SelfSigned);
        assert_eq!(GenerationMode::Csr, GenerationMode::Csr);
        assert_ne!(GenerationMode::SelfSigned, GenerationMode::Csr);
    }
}
