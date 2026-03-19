//! Certificate chain view rendering.

use crate::cert::{CertChain, ChainPosition, ChainValidationStatus, SignatureStatus};
use crate::theme::{self, ThemeMode};
use egui::{CornerRadius, Frame, Margin, RichText, ScrollArea, Stroke, Ui};

/// Draw certificate chain view.
pub(crate) fn draw_chain(ui: &mut Ui, chain: &CertChain, theme_mode: ThemeMode) {
    let text_primary = theme::text_primary(theme_mode);
    let text_secondary = theme::text_secondary(theme_mode);
    let text_label = theme::text_label(theme_mode);
    let text_value = theme::text_value(theme_mode);
    let bg_secondary = theme::bg_secondary(theme_mode);
    let border_color = theme::border(theme_mode);

    // Chain status header
    let (status_text, status_color) = match chain.validation_status {
        ChainValidationStatus::Valid => ("Valid Chain".to_string(), egui::Color32::GREEN),
        ChainValidationStatus::Incomplete { missing_count } => (
            format!("Incomplete Chain ({} missing)", missing_count),
            egui::Color32::YELLOW,
        ),
        ChainValidationStatus::BrokenLinks => ("Broken Links".to_string(), egui::Color32::RED),
        ChainValidationStatus::Empty => ("Empty Chain".to_string(), egui::Color32::GRAY),
    };

    Frame::new()
        .fill(bg_secondary)
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, border_color))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Certificate Chain")
                            .size(theme::FONT_TITLE)
                            .color(text_primary)
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
                ui.label(
                    RichText::new(format!("{} certificate(s)", chain.certificates.len()))
                        .size(theme::FONT_BODY)
                        .color(text_secondary),
                );
                #[cfg(feature = "network")]
                if let Some(ref err) = chain.completion_error {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(err)
                                .size(theme::FONT_BODY)
                                .color(egui::Color32::RED),
                        );
                    });
                }
            });
        });

    ui.add_space(theme::SECTION_SPACING);

    // Draw chain as tree
    ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for (i, chain_cert) in chain.certificates.iter().enumerate() {
                draw_chain_cert(
                    ui,
                    chain_cert,
                    i,
                    chain.certificates.len(),
                    bg_secondary,
                    text_primary,
                    text_secondary,
                    text_label,
                    text_value,
                );
                ui.add_space(8.0);
            }
        });
}

/// Draw a single certificate in the chain view.
#[allow(clippy::too_many_arguments)]
fn draw_chain_cert(
    ui: &mut Ui,
    chain_cert: &crate::cert::ChainCert,
    index: usize,
    total: usize,
    bg_secondary: egui::Color32,
    text_primary: egui::Color32,
    text_secondary: egui::Color32,
    text_label: egui::Color32,
    text_value: egui::Color32,
) {
    let position_text = match chain_cert.position {
        ChainPosition::Leaf => "Leaf",
        ChainPosition::Intermediate { depth } => &format!("Intermediate (depth {})", depth),
        ChainPosition::Root => "Root CA",
    };

    let position_color = match chain_cert.position {
        ChainPosition::Leaf => egui::Color32::from_rgb(100, 200, 100),
        ChainPosition::Intermediate { .. } => egui::Color32::from_rgb(100, 150, 200),
        ChainPosition::Root => egui::Color32::from_rgb(200, 150, 100),
    };

    let border_color_actual = match chain_cert.signature_status {
        SignatureStatus::Valid => egui::Color32::from_rgb(100, 200, 100),
        SignatureStatus::Invalid => egui::Color32::RED,
        SignatureStatus::Unknown => egui::Color32::from_rgb(200, 180, 50),
    };

    Frame::new()
        .fill(bg_secondary)
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::same(10))
        .stroke(Stroke::new(2.0, border_color_actual))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                // Position indicator
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(position_text)
                            .size(theme::FONT_HEADING)
                            .color(position_color)
                            .strong(),
                    );
                    ui.label(
                        RichText::new(format!("{} / {}", index + 1, total))
                            .size(theme::FONT_BODY)
                            .color(text_secondary),
                    );
                });

                ui.add_space(4.0);

                // Certificate name
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&chain_cert.cert.display_name)
                            .size(theme::FONT_BODY)
                            .color(text_primary)
                            .strong(),
                    );
                });

                ui.add_space(4.0);

                // Subject
                ui.label(
                    RichText::new("Subject:")
                        .size(theme::FONT_BODY)
                        .color(text_label),
                );
                ui.label(
                    RichText::new(&chain_cert.cert.subject)
                        .size(theme::FONT_BODY)
                        .color(text_value),
                );

                // Issuer
                ui.label(
                    RichText::new("Issuer:")
                        .size(theme::FONT_BODY)
                        .color(text_label),
                );
                ui.label(
                    RichText::new(&chain_cert.cert.issuer)
                        .size(theme::FONT_BODY)
                        .color(text_value),
                );

                // Validity
                let validity_color = theme::validity_color(chain_cert.cert.validity_status);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Validity:")
                            .size(theme::FONT_BODY)
                            .color(text_label),
                    );
                    ui.label(
                        RichText::new(theme::validity_text(chain_cert.cert.validity_status))
                            .size(theme::FONT_BODY)
                            .color(validity_color),
                    );
                });

                // Signature verification status
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Signature:")
                            .size(theme::FONT_BODY)
                            .color(text_label),
                    );
                    let (sig_text, sig_color) = match chain_cert.signature_status {
                        SignatureStatus::Valid => ("Valid", egui::Color32::GREEN),
                        SignatureStatus::Invalid => ("Invalid", egui::Color32::RED),
                        SignatureStatus::Unknown => {
                            ("Unknown", egui::Color32::from_rgb(200, 180, 50))
                        }
                    };
                    ui.label(
                        RichText::new(sig_text)
                            .size(theme::FONT_BODY)
                            .color(sig_color),
                    );
                });
            });
        });
}
