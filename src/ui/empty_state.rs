//! Empty state page rendering.

use crate::theme::{self, ThemeMode};
use egui::{Button, CornerRadius, RichText, Sense, Ui};

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

pub(crate) fn draw_empty_state(ui: &mut Ui, theme_mode: ThemeMode, on_open: &mut dyn FnMut()) {
    let text_secondary = theme::text_secondary(theme_mode);
    let text_label = theme::text_label(theme_mode);
    let accent = theme::accent(theme_mode);

    ui.vertical_centered(|ui| {
        ui.add_space(60.0);

        // Title
        ui.label(
            RichText::new("No certificate or CSR loaded")
                .size(22.0)
                .color(text_secondary)
                .strong(),
        );
        ui.add_space(16.0);

        // Supported formats
        ui.label(
            RichText::new("Supported formats:")
                .size(13.0)
                .color(text_secondary),
        );
        ui.add_space(4.0);
        let formats = ".pem  .crt  .cer  .der  .csr  .p12  .pfx";
        ui.label(RichText::new(formats).size(14.0).color(text_label));

        ui.add_space(20.0);

        // Open File button
        let open_btn = Button::new(
            RichText::new("  Open File  ")
                .size(16.0)
                .color(egui::Color32::WHITE)
                .strong(),
        )
        .fill(accent)
        .corner_radius(CornerRadius::same(6))
        .sense(Sense::click());

        if ui.add(open_btn).clicked() {
            on_open();
        }

        ui.add_space(24.0);

        // Drag and drop hint
        ui.label(
            RichText::new("or drag & drop certificate files here")
                .size(13.0)
                .color(text_secondary),
        );

        ui.add_space(16.0);

        // Keyboard shortcuts
        ui.label(
            RichText::new("Keyboard shortcuts:")
                .size(12.0)
                .color(text_secondary),
        );
        ui.add_space(4.0);

        let shortcuts_text = format!(
            "{}+O: Open files  |  {}+W: Close tab",
            mod_label(),
            mod_label()
        );
        ui.label(
            RichText::new(shortcuts_text)
                .size(11.0)
                .color(text_secondary),
        );
    });
}
