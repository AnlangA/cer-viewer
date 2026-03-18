//! Visual theme and styling constants for the certificate viewer.

use egui::{Color32, CornerRadius, FontFamily, FontId, Stroke, Vec2, Visuals};

// ── Color palette ──────────────────────────────────────────────────

pub const BG_PRIMARY: Color32 = Color32::from_rgb(24, 24, 32);
pub const BG_SECONDARY: Color32 = Color32::from_rgb(32, 33, 44);
pub const BG_HOVER: Color32 = Color32::from_rgb(42, 43, 56);
pub const BG_HEADER: Color32 = Color32::from_rgb(38, 40, 54);

pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(220, 220, 230);
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(150, 155, 170);
pub const TEXT_LABEL: Color32 = Color32::from_rgb(130, 170, 255);
pub const TEXT_VALUE: Color32 = Color32::from_rgb(195, 210, 230);

pub const ACCENT: Color32 = Color32::from_rgb(100, 140, 255);
pub const ACCENT_DIM: Color32 = Color32::from_rgb(70, 100, 200);
pub const BORDER: Color32 = Color32::from_rgb(55, 58, 75);

// Status colors for certificate validity
pub const STATUS_VALID: Color32 = Color32::from_rgb(80, 200, 120);
pub const STATUS_NOT_YET_VALID: Color32 = Color32::from_rgb(255, 200, 80);
pub const STATUS_EXPIRED: Color32 = Color32::from_rgb(255, 100, 100);

// Special indicator color for valid leaf certificates in tabs
pub const LEAF_INDICATOR: Color32 = Color32::from_rgb(255, 200, 80);

// Banner colors
pub const BANNER_INFO_BG: Color32 = Color32::from_rgb(30, 80, 50);
pub const BANNER_INFO_TEXT: Color32 = Color32::from_rgb(120, 255, 180);
pub const BANNER_INFO_VALUE: Color32 = Color32::from_rgb(200, 255, 220);
pub const BANNER_ERROR_BG: Color32 = Color32::from_rgb(80, 30, 30);
pub const BANNER_ERROR_TEXT: Color32 = Color32::from_rgb(255, 120, 120);

// ── Font sizes ─────────────────────────────────────────────────────

pub const FONT_TITLE: f32 = 18.0;
pub const FONT_HEADING: f32 = 14.0;
pub const FONT_BODY: f32 = 13.0;
pub const FONT_MONO: f32 = 12.0;

// ── Spacing ────────────────────────────────────────────────────────

pub const ITEM_SPACING: Vec2 = Vec2::new(8.0, 4.0);
pub const SECTION_SPACING: f32 = 12.0;

// ── Helpers ────────────────────────────────────────────────────────

/// Font ID for monospaced text (hex values, OIDs, etc.).
pub fn mono_font() -> FontId {
    FontId::new(FONT_MONO, FontFamily::Monospace)
}

/// Font ID for body text.
pub fn body_font() -> FontId {
    FontId::new(FONT_BODY, FontFamily::Proportional)
}

/// Get status color based on validity status.
pub fn validity_color(status: crate::cert::ValidityStatus) -> Color32 {
    use crate::cert::ValidityStatus;
    match status {
        ValidityStatus::Valid => STATUS_VALID,
        ValidityStatus::NotYetValid => STATUS_NOT_YET_VALID,
        ValidityStatus::Expired => STATUS_EXPIRED,
    }
}

/// Get status text based on validity status.
pub fn validity_text(status: crate::cert::ValidityStatus) -> &'static str {
    use crate::cert::ValidityStatus;
    match status {
        ValidityStatus::Valid => "[OK] Valid",
        ValidityStatus::NotYetValid => "[!] Not Yet Valid",
        ValidityStatus::Expired => "[X] Expired",
    }
}

/// Apply the dark modern theme to the egui context.
pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    visuals.panel_fill = BG_PRIMARY;
    visuals.window_fill = BG_SECONDARY;
    visuals.faint_bg_color = BG_SECONDARY;
    visuals.extreme_bg_color = Color32::from_rgb(16, 16, 22);

    visuals.widgets.noninteractive.bg_fill = BG_SECONDARY;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(6);

    visuals.widgets.inactive.bg_fill = BG_SECONDARY;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_SECONDARY);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(6);

    visuals.widgets.hovered.bg_fill = BG_HOVER;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(6);

    visuals.widgets.active.bg_fill = ACCENT_DIM;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.corner_radius = CornerRadius::same(6);

    visuals.selection.bg_fill = ACCENT_DIM;
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);

    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.window_stroke = Stroke::new(1.0, BORDER);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = ITEM_SPACING;
    style.spacing.window_margin = egui::Margin::same(16);
    ctx.set_style(style);
}
