//! Toolbar panel rendering.

use crate::theme::{self, ThemeMode};
use crate::ui::app::CertViewerApp;
use crate::ui::tab_bar::TabAction;
use egui::{Context, CornerRadius, Frame, Key, KeyboardShortcut, Margin, RichText, Stroke, Vec2};

// ── Keyboard shortcuts ──────────────────────────────────────────────

pub(crate) const OPEN_FILES_SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(egui::Modifiers::COMMAND, Key::O);
pub(crate) const CLOSE_TAB_SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(egui::Modifiers::COMMAND, Key::W);

/// Platform-appropriate modifier label ("Cmd" on macOS, "Ctrl" elsewhere).
fn mod_label() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Cmd"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "Ctrl"
    }
}

/// Draw the top toolbar panel (title, buttons, shortcut hints, tab bar).
pub(crate) fn draw_toolbar(ctx: &Context, app: &mut CertViewerApp) {
    let theme_mode = app.theme_mode;
    let text_primary = theme::text_primary(theme_mode);
    let text_secondary = theme::text_secondary(theme_mode);
    let accent = theme::accent(theme_mode);
    let bg_header = theme::bg_header(theme_mode);
    let border_color = theme::border(theme_mode);
    let bg_secondary = theme::bg_secondary(theme_mode);

    egui::TopBottomPanel::top("toolbar")
        .frame(
            Frame::new()
                .fill(bg_header)
                .inner_margin(Margin::symmetric(12, 8))
                .stroke(Stroke::new(1.0, border_color)),
        )
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Certificate Viewer")
                        .size(theme::FONT_TITLE)
                        .color(accent)
                        .strong(),
                );

                ui.add_space(16.0);
                ui.separator();
                ui.add_space(8.0);

                let btn = egui::Button::new(RichText::new("Open Files...").size(theme::FONT_BODY))
                    .corner_radius(CornerRadius::same(4));
                if ui.add(btn).clicked() {
                    app.open_file_dialog();
                }

                // Open Recent submenu
                if !app.recent_files.is_empty() {
                    ui.menu_button(RichText::new("Open Recent").size(theme::FONT_BODY), |ui| {
                        let mut open_path: Option<String> = None;
                        for recent_path in &app.recent_files {
                            let file_name = std::path::Path::new(recent_path)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or(recent_path);
                            if ui.button(file_name).clicked() {
                                open_path = Some(recent_path.clone());
                                ui.close();
                            }
                        }
                        if let Some(path) = open_path {
                            let path_buf = std::path::PathBuf::from(&path);
                            app.load_files(vec![path_buf]);
                        }
                    });
                }

                if !app.documents.is_empty() {
                    let clear_btn =
                        egui::Button::new(RichText::new("Clear All").size(theme::FONT_BODY))
                            .corner_radius(CornerRadius::same(4));
                    if ui.add(clear_btn).clicked() {
                        app.clear_all_documents();
                    }
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);

                // Theme toggle button
                let theme_icon = match theme_mode {
                    ThemeMode::Dark => "\u{2600}",  // sun
                    ThemeMode::Light => "\u{263D}", // moon
                };
                let theme_btn =
                    egui::Button::new(RichText::new(theme_icon).size(theme::FONT_TITLE))
                        .corner_radius(CornerRadius::same(4));
                if ui.add(theme_btn).clicked() {
                    app.toggle_theme();
                }

                ui.add_space(8.0);
                ui.separator();
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "{}+O: Open | {}+W: Close",
                        mod_label(),
                        mod_label()
                    ))
                    .size(11.0)
                    .color(text_secondary),
                );
            });

            // Tab bar for documents
            if !app.documents.is_empty() {
                ui.add_space(4.0);

                let tab_data: Vec<(
                    usize,
                    String,
                    bool,
                    bool,
                    Option<crate::cert::ValidityStatus>,
                )> = app
                    .documents
                    .iter()
                    .enumerate()
                    .map(|(i, doc)| {
                        let prefix = if doc.is_csr() { "[R] " } else { "[C] " };
                        let name = doc.display_name();
                        let label = if name.chars().count() > 20 {
                            let truncated: String = name.chars().take(17).collect();
                            format!("{}{}...", prefix, truncated)
                        } else {
                            format!("{}{}", prefix, name)
                        };
                        let validity = match doc {
                            crate::document::Document::Certificate(c) => Some(c.validity_status),
                            _ => None,
                        };
                        (i, label, i == app.selected_tab, doc.is_csr(), validity)
                    })
                    .collect();

                let mut action: Option<TabAction> = None;

                egui::ScrollArea::horizontal()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            for (i, label, is_selected, is_csr, validity) in &tab_data {
                                let tab_frame = Frame::new()
                                    .fill(if *is_selected {
                                        bg_secondary
                                    } else {
                                        egui::Color32::TRANSPARENT
                                    })
                                    .corner_radius(CornerRadius::same(4))
                                    .inner_margin(Margin::symmetric(8, 4))
                                    .stroke(if *is_selected {
                                        Stroke::new(1.0, accent)
                                    } else {
                                        Stroke::new(1.0, border_color)
                                    });

                                let tab_response = tab_frame.show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.spacing_mut().item_spacing = Vec2::new(6.0, 0.0);

                                        // Indicator dot
                                        let indicator_color = if *is_csr {
                                            theme::CSR_INDICATOR
                                        } else if let Some(validity) = validity {
                                            if app.is_leaf_cert(*i) {
                                                theme::LEAF_INDICATOR
                                            } else {
                                                theme::validity_color(*validity)
                                            }
                                        } else {
                                            text_secondary
                                        };
                                        ui.label(RichText::new("*").color(indicator_color));

                                        let text = RichText::new(label)
                                            .size(theme::FONT_BODY)
                                            .color(if *is_selected {
                                                text_primary
                                            } else {
                                                text_secondary
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

                                // Right-click context menu on tabs
                                tab_response.response.context_menu(|ui| {
                                    let tab_idx = *i;
                                    let total = app.documents.len();

                                    if ui.button("Close").clicked() {
                                        action = Some(TabAction::Close(tab_idx));
                                        ui.close();
                                    }

                                    if total > 1 && ui.button("Close Others").clicked() {
                                        action = Some(TabAction::CloseOthers(tab_idx));
                                        ui.close();
                                    }

                                    if ui.button("Close All").clicked() {
                                        action = Some(TabAction::CloseAll);
                                        ui.close();
                                    }

                                    if tab_idx < total - 1 && ui.button("Close Right").clicked() {
                                        action = Some(TabAction::CloseRight(tab_idx));
                                        ui.close();
                                    }
                                });

                                ui.add_space(2.0);
                            }
                        });
                    });

                if let Some(act) = action {
                    match act {
                        TabAction::Select(i) => app.selected_tab = i,
                        TabAction::Close(i) => app.remove_document(i),
                        TabAction::CloseOthers(keep_idx) => {
                            // Close all tabs except the one at keep_idx.
                            // Collect indices to close (from high to low to preserve indices).
                            let close_indices: Vec<usize> = (0..app.documents.len())
                                .filter(|&j| j != keep_idx)
                                .collect();
                            // Close from highest index first
                            for &idx in close_indices.iter().rev() {
                                app.remove_document(idx);
                            }
                        }
                        TabAction::CloseAll => {
                            app.clear_all_documents();
                        }
                        TabAction::CloseRight(from_idx) => {
                            // Close all tabs with index > from_idx.
                            // Collect indices to close.
                            let close_indices: Vec<usize> =
                                (from_idx + 1..app.documents.len()).collect();
                            for &idx in close_indices.iter().rev() {
                                app.remove_document(idx);
                            }
                        }
                    }
                }
            }
        });
}
