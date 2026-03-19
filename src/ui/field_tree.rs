//! Recursive collapsible field tree rendering.

use crate::cert::CertField;
use crate::security::is_potentially_sensitive;
use crate::theme::{self, ThemeMode};
use egui::{CollapsingHeader, CornerRadius, Frame, Id, Margin, RichText, Stroke, Ui};

/// Check if a field or any of its descendants match the search query (case-insensitive).
fn field_matches_search(field: &CertField, query: &str) -> bool {
    let query_lower = query.to_lowercase();

    if field.label.to_lowercase().contains(&query_lower) {
        return true;
    }

    if let Some(ref val) = field.value {
        if val.to_lowercase().contains(&query_lower) {
            return true;
        }
    }

    field
        .children
        .iter()
        .any(|child| field_matches_search(child, &query_lower))
}

pub(crate) fn draw_field<F>(
    ui: &mut Ui,
    field: &CertField,
    depth: usize,
    on_copy: &mut F,
    theme_mode: ThemeMode,
    search_filter: &str,
) where
    F: FnMut(String),
{
    // When search is active, skip fields that don't match
    if !search_filter.is_empty() && !field_matches_search(field, search_filter) {
        return;
    }

    let id = Id::new(&field.label)
        .with(depth)
        .with(field.value.as_deref().unwrap_or("").get(..20).unwrap_or(""));

    let bg_secondary = theme::bg_secondary(theme_mode);
    let border_color = theme::border(theme_mode);
    let text_primary = theme::text_primary(theme_mode);
    let text_label = theme::text_label(theme_mode);
    let text_secondary = theme::text_secondary(theme_mode);
    let text_value = theme::text_value(theme_mode);

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
                "Extensions" | "Extension Request" => "[X]",
                "Attributes" => "[A]",
                "Fingerprints" => "[F]",
                _ => "[*]",
            }
        } else {
            ">"
        };

        // When searching, auto-expand containers that have matching descendants
        let force_open = !search_filter.is_empty() && field_matches_search(field, search_filter);

        Frame::new()
            .fill(if is_root {
                bg_secondary
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
                Stroke::new(1.0, border_color)
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
                    .color(if depth == 0 { text_primary } else { text_label })
                    .strong();

                CollapsingHeader::new(header)
                    .id_salt(id)
                    .default_open(
                        force_open || (is_root && !field.label.contains("Signature Value")),
                    )
                    .show(ui, |ui| {
                        if let Some(ref val) = field.value {
                            ui.horizontal_wrapped(|ui| {
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(val)
                                        .font(theme::mono_font())
                                        .color(text_value),
                                );
                            });
                            ui.add_space(2.0);
                        }
                        for child in &field.children {
                            draw_field(ui, child, depth + 1, on_copy, theme_mode, search_filter);
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
                    .color(text_label),
            );
            if let Some(ref val) = field.value {
                ui.label(
                    RichText::new(" : ")
                        .color(text_secondary)
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
                        .color(text_value),
                );

                response.context_menu(|ui| {
                    let is_sensitive = is_potentially_sensitive(&field.label, Some(val));

                    if is_sensitive {
                        ui.label(
                            RichText::new("Sensitive data")
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
