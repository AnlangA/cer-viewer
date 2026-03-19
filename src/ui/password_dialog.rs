//! PKCS#12 password dialog — a stub UI for entering PKCS#12 passwords.
//!
//! This module provides a simple password input dialog. The full PKCS#12
//! parsing requires the `pkcs12` feature which uses a pre-release crate.

#![allow(dead_code)] // Module is not yet wired into the main app

use crate::theme;
use egui::RichText;

/// State for the password dialog.
pub struct PasswordDialog {
    /// The password being entered (stored in plaintext for PKCS#12 decryption).
    password: String,
    /// Whether the dialog is currently visible.
    visible: bool,
    /// Optional callback result.
    pub result: Option<String>,
}

impl PasswordDialog {
    /// Create a new password dialog.
    pub fn new() -> Self {
        Self {
            password: String::new(),
            visible: false,
            result: None,
        }
    }

    /// Show the password dialog.
    pub fn show(&mut self) {
        self.visible = true;
        self.password.clear();
        self.result = None;
    }

    /// Hide the password dialog.
    pub fn hide(&mut self) {
        self.visible = false;
        self.password.clear();
    }

    /// Check if the dialog is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Take the password result, clearing it from the dialog.
    pub fn take_result(&mut self) -> Option<String> {
        self.result.take()
    }

    /// Draw the password dialog.
    ///
    /// Returns `true` if the dialog consumed input (caller should not process
    /// other keyboard events in that frame).
    pub fn draw(&mut self, ui: &mut egui::Ui) -> bool {
        if !self.visible {
            return false;
        }

        let mut consumed = false;

        // Draw the dialog as a floating panel
        let area = egui::Area::new(egui::Id::new("password_dialog_area"))
            .fixed_pos(ui.available_rect_before_wrap().center())
            .order(egui::Order::Foreground);

        area.show(ui.ctx(), |ui| {
            let frame = egui::Frame::new()
                .fill(theme::BG_SECONDARY)
                .inner_margin(egui::Margin::same(16))
                .corner_radius(egui::CornerRadius::same(8))
                .stroke((1.0, theme::BORDER));

            frame.show(ui, |ui| {
                ui.set_width(350.0);
                ui.vertical_centered(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Enter PKCS#12 Password")
                            .size(theme::FONT_HEADING)
                            .color(theme::TEXT_PRIMARY),
                    );
                    ui.add_space(12.0);

                    ui.label(
                        RichText::new("Password:")
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_LABEL),
                    );
                    ui.add_space(4.0);

                    // Password input field
                    let response = ui.add_sized(
                        egui::vec2(300.0, 28.0),
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .desired_width(300.0),
                    );
                    consumed = response.changed();
                    response.request_focus();

                    ui.add_space(12.0);

                    // Buttons
                    ui.horizontal(|ui| {
                        ui.add_space(60.0);
                        if ui
                            .add(
                                egui::Button::new(RichText::new("Cancel").size(theme::FONT_BODY))
                                    .corner_radius(egui::CornerRadius::same(4))
                                    .fill(theme::BG_HOVER),
                            )
                            .clicked()
                        {
                            self.hide();
                            consumed = true;
                        }

                        ui.add_space(8.0);

                        if ui
                            .add(
                                egui::Button::new(RichText::new("OK").size(theme::FONT_BODY))
                                    .corner_radius(egui::CornerRadius::same(4))
                                    .fill(theme::ACCENT),
                            )
                            .clicked()
                        {
                            self.result = Some(self.password.clone());
                            self.hide();
                            consumed = true;
                        }
                    });
                    ui.add_space(8.0);
                });
            });
        });

        consumed
    }
}

impl Default for PasswordDialog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_dialog_initial_state() {
        let dialog = PasswordDialog::new();
        assert!(!dialog.is_visible());
        assert!(dialog.result.is_none());
    }

    #[test]
    fn test_password_dialog_show_hide() {
        let mut dialog = PasswordDialog::new();
        dialog.show();
        assert!(dialog.is_visible());
        assert!(dialog.result.is_none());
        dialog.hide();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_password_dialog_take_result() {
        let mut dialog = PasswordDialog::new();
        dialog.result = Some("secret".to_string());
        let result = dialog.take_result();
        assert_eq!(result, Some("secret".to_string()));
        assert!(dialog.result.is_none());
    }

    #[test]
    fn test_password_dialog_default() {
        let dialog = PasswordDialog::default();
        assert!(!dialog.is_visible());
    }
}
