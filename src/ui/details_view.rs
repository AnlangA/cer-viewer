//! Certificate and CSR detail rendering.

use crate::cert::ParsedCert;
use crate::document::Document;
use crate::theme::{self, ThemeMode};
use crate::ui::field_tree::draw_field;
use chrono::TimeZone;
use egui::{CornerRadius, Frame, Margin, RichText, ScrollArea, Stroke, Ui};

/// Draw a document (certificate or CSR) card and field tree.
pub(crate) fn draw_document<F>(
    ui: &mut Ui,
    doc: &Document,
    on_copy: &mut F,
    theme_mode: ThemeMode,
    search_filter: &str,
) where
    F: FnMut(String),
{
    match doc {
        Document::Certificate(cert) => {
            draw_certificate(ui, cert, on_copy, theme_mode, search_filter)
        }
        Document::Csr(csr) => draw_csr(ui, csr, on_copy, theme_mode, search_filter),
    }
}

pub(crate) fn draw_certificate<F>(
    ui: &mut Ui,
    cert: &ParsedCert,
    on_copy: &mut F,
    theme_mode: ThemeMode,
    search_filter: &str,
) where
    F: FnMut(String),
{
    let status_text = theme::validity_text(cert.validity_status);
    let status_color = theme::validity_color(cert.validity_status);

    let bg_secondary = theme::bg_secondary(theme_mode);
    let border_color = theme::border(theme_mode);
    let text_primary = theme::text_primary(theme_mode);
    let text_secondary = theme::text_secondary(theme_mode);

    Frame::new()
        .fill(bg_secondary)
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, border_color))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&cert.display_name)
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
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(&cert.not_before)
                            .size(theme::FONT_BODY)
                            .color(text_secondary),
                    );
                    ui.label(
                        RichText::new(" -> ")
                            .size(theme::FONT_BODY)
                            .color(text_secondary),
                    );
                    ui.label(
                        RichText::new(&cert.not_after)
                            .size(theme::FONT_BODY)
                            .color(text_secondary),
                    );
                });

                // Expiry countdown
                if let Some(countdown_text) = expiry_countdown(cert) {
                    ui.add_space(2.0);
                    ui.label(
                        RichText::new(countdown_text)
                            .size(theme::FONT_BODY)
                            .color(status_color),
                    );
                }

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
                draw_field(ui, field, 0, on_copy, theme_mode, search_filter);
            }
        });
}

/// Compute expiry countdown text based on the not_after timestamp.
///
/// Parses the `not_after` string (which is formatted as a human-readable date)
/// to calculate days until expiry or days since expiry.
fn expiry_countdown(cert: &ParsedCert) -> Option<String> {
    // Try to parse the not_after string as a DateTime
    // The certificate stores not_after as a formatted string from ASN1Time.
    // We need to parse it back. The format used by x509_parser's ASN1Time
    // display is typically "YYYY-MM-DD HH:MM:SS (UTC)" or similar.
    let not_after_str = cert.not_after.trim();

    // Try common date formats
    let not_after_dt = parse_not_after_datetime(not_after_str)?;

    let now = chrono::Utc::now();
    let duration = not_after_dt.signed_duration_since(now);
    let days = duration.num_days();

    if days > 0 {
        if days == 1 {
            Some("1 day until expiry".to_string())
        } else {
            Some(format!("{} days until expiry", days))
        }
    } else if days == 0 {
        Some("Expires today".to_string())
    } else {
        let days_ago = -days;
        if days_ago == 1 {
            Some("Expired 1 day ago".to_string())
        } else {
            Some(format!("Expired {} days ago", days_ago))
        }
    }
}

/// Try to parse the not_after datetime string from various formats.
fn parse_not_after_datetime(s: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    // x509_parser ASN1Time to_string() format: "2025-01-01 00:00:00 (UTC)"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S (UTC)") {
        return Some(chrono::Utc.from_utc_datetime(&dt));
    }

    // Fallback: try "YYYY-MM-DD HH:MM:SS"
    if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(chrono::Utc.from_utc_datetime(&dt));
    }

    // Fallback: try "YYYY-MM-DDTHH:MM:SSZ"
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&chrono::Utc));
    }

    None
}

pub(crate) fn draw_csr<F>(
    ui: &mut Ui,
    csr: &crate::formats::csr::ParsedCsr,
    on_copy: &mut F,
    theme_mode: ThemeMode,
    search_filter: &str,
) where
    F: FnMut(String),
{
    let bg_secondary = theme::bg_secondary(theme_mode);
    let border_color = theme::border(theme_mode);
    let text_primary = theme::text_primary(theme_mode);
    let text_label = theme::text_label(theme_mode);
    let text_value = theme::text_value(theme_mode);

    Frame::new()
        .fill(bg_secondary)
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, border_color))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&csr.display_name)
                            .size(theme::FONT_TITLE)
                            .color(text_primary)
                            .strong(),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("[CSR]")
                            .size(theme::FONT_BODY)
                            .color(theme::CSR_INDICATOR),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new("Signature: ")
                            .size(theme::FONT_BODY)
                            .color(text_label),
                    );
                    ui.label(
                        RichText::new(&csr.signature_algorithm)
                            .size(theme::FONT_BODY)
                            .color(text_value),
                    );
                });

                ui.add_space(4.0);

                // Quick actions
                ui.horizontal(|ui| {
                    let copy_btn =
                        egui::Button::new(RichText::new("Copy PEM").size(theme::FONT_BODY))
                            .corner_radius(CornerRadius::same(4));
                    if ui.add(copy_btn).clicked() {
                        on_copy(csr.to_pem());
                    }
                });
            });
        });

    ui.add_space(theme::SECTION_SPACING);

    ScrollArea::vertical()
        .auto_shrink([false; 2])
        .show(ui, |ui| {
            for field in &csr.fields {
                draw_field(ui, field, 0, on_copy, theme_mode, search_filter);
            }
        });
}
