//! Visual theme and styling constants for the certificate viewer.

use egui::{Color32, CornerRadius, FontFamily, FontId, Stroke, Vec2, Visuals};

/// Theme mode for the application.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub enum ThemeMode {
    /// Dark theme (default).
    #[default]
    Dark,
    /// Light theme.
    Light,
}

// ── Dark color palette ─────────────────────────────────────────────

pub const BG_PRIMARY: Color32 = Color32::from_rgb(24, 24, 32);
pub const BG_SECONDARY: Color32 = Color32::from_rgb(32, 33, 44);
pub const BG_HOVER: Color32 = Color32::from_rgb(42, 43, 56);
pub const BG_HEADER: Color32 = Color32::from_rgb(38, 40, 54);
#[allow(dead_code)]
pub const BG_TERTIARY: Color32 = Color32::from_rgb(28, 28, 38);

pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(220, 220, 230);
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(150, 155, 170);
pub const TEXT_LABEL: Color32 = Color32::from_rgb(130, 170, 255);
pub const TEXT_VALUE: Color32 = Color32::from_rgb(195, 210, 230);

pub const ACCENT: Color32 = Color32::from_rgb(100, 140, 255);
pub const ACCENT_DIM: Color32 = Color32::from_rgb(70, 100, 200);
pub const BORDER: Color32 = Color32::from_rgb(55, 58, 75);

// ── Light color palette ────────────────────────────────────────────

pub const LIGHT_BG_PRIMARY: Color32 = Color32::from_rgb(245, 245, 250);
pub const LIGHT_BG_SECONDARY: Color32 = Color32::from_rgb(255, 255, 255);
pub const LIGHT_BG_HOVER: Color32 = Color32::from_rgb(230, 233, 245);
pub const LIGHT_BG_HEADER: Color32 = Color32::from_rgb(240, 242, 248);

pub const LIGHT_TEXT_PRIMARY: Color32 = Color32::from_rgb(30, 30, 40);
pub const LIGHT_TEXT_SECONDARY: Color32 = Color32::from_rgb(100, 105, 120);
pub const LIGHT_TEXT_LABEL: Color32 = Color32::from_rgb(40, 80, 180);
pub const LIGHT_TEXT_VALUE: Color32 = Color32::from_rgb(50, 60, 80);

pub const LIGHT_ACCENT: Color32 = Color32::from_rgb(60, 100, 220);
pub const LIGHT_ACCENT_DIM: Color32 = Color32::from_rgb(80, 120, 200);
pub const LIGHT_BORDER: Color32 = Color32::from_rgb(200, 205, 215);

// Status colors for certificate validity (shared between themes)
pub const STATUS_VALID: Color32 = Color32::from_rgb(80, 200, 120);
pub const STATUS_NOT_YET_VALID: Color32 = Color32::from_rgb(255, 200, 80);
pub const STATUS_EXPIRED: Color32 = Color32::from_rgb(255, 100, 100);

// Special indicator color for valid leaf certificates in tabs
pub const LEAF_INDICATOR: Color32 = Color32::from_rgb(255, 200, 80);

// Foreground colors for diff/compare views
#[allow(dead_code)]
pub const VALID_FG: Color32 = Color32::from_rgb(80, 200, 120);
#[allow(dead_code)]
pub const WARNING_FG: Color32 = Color32::from_rgb(255, 200, 80);

// CSR tab indicator color
pub const CSR_INDICATOR: Color32 = Color32::from_rgb(100, 180, 255);

// ── Banner colors (dark) ───────────────────────────────────────────

pub const BANNER_INFO_BG: Color32 = Color32::from_rgb(30, 80, 50);
pub const BANNER_INFO_TEXT: Color32 = Color32::from_rgb(120, 255, 180);
pub const BANNER_INFO_VALUE: Color32 = Color32::from_rgb(200, 255, 220);
pub const BANNER_ERROR_BG: Color32 = Color32::from_rgb(80, 30, 30);
pub const BANNER_ERROR_TEXT: Color32 = Color32::from_rgb(255, 120, 120);

// ── Banner colors (light) ──────────────────────────────────────────

pub const LIGHT_BANNER_INFO_BG: Color32 = Color32::from_rgb(220, 245, 230);
pub const LIGHT_BANNER_INFO_TEXT: Color32 = Color32::from_rgb(20, 120, 60);
pub const LIGHT_BANNER_INFO_VALUE: Color32 = Color32::from_rgb(30, 80, 50);
pub const LIGHT_BANNER_ERROR_BG: Color32 = Color32::from_rgb(255, 230, 230);
pub const LIGHT_BANNER_ERROR_TEXT: Color32 = Color32::from_rgb(200, 30, 30);

// ── Font sizes ─────────────────────────────────────────────────────

pub const FONT_TITLE: f32 = 18.0;
pub const FONT_HEADING: f32 = 14.0;
pub const FONT_BODY: f32 = 13.0;
pub const FONT_MONO: f32 = 12.0;
#[allow(dead_code)]
pub const FONT_SMALL: f32 = 11.0;

// ── Spacing ────────────────────────────────────────────────────────

pub const ITEM_SPACING: Vec2 = Vec2::new(8.0, 4.0);
pub const SECTION_SPACING: f32 = 12.0;

// ── Theme-aware color access ───────────────────────────────────────

/// Returns the current theme's primary background color.
pub fn bg_primary(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BG_PRIMARY,
        ThemeMode::Light => LIGHT_BG_PRIMARY,
    }
}

/// Returns the current theme's secondary background color.
pub fn bg_secondary(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BG_SECONDARY,
        ThemeMode::Light => LIGHT_BG_SECONDARY,
    }
}

/// Returns the current theme's hover background color.
#[allow(dead_code)]
pub fn bg_hover(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BG_HOVER,
        ThemeMode::Light => LIGHT_BG_HOVER,
    }
}

/// Returns the current theme's header background color.
pub fn bg_header(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BG_HEADER,
        ThemeMode::Light => LIGHT_BG_HEADER,
    }
}

/// Returns the current theme's primary text color.
pub fn text_primary(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => TEXT_PRIMARY,
        ThemeMode::Light => LIGHT_TEXT_PRIMARY,
    }
}

/// Returns the current theme's secondary text color.
pub fn text_secondary(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => TEXT_SECONDARY,
        ThemeMode::Light => LIGHT_TEXT_SECONDARY,
    }
}

/// Returns the current theme's label text color.
pub fn text_label(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => TEXT_LABEL,
        ThemeMode::Light => LIGHT_TEXT_LABEL,
    }
}

/// Returns the current theme's value text color.
pub fn text_value(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => TEXT_VALUE,
        ThemeMode::Light => LIGHT_TEXT_VALUE,
    }
}

/// Returns the current theme's accent color.
pub fn accent(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => ACCENT,
        ThemeMode::Light => LIGHT_ACCENT,
    }
}

/// Returns the current theme's dim accent color.
#[allow(dead_code)]
pub fn accent_dim(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => ACCENT_DIM,
        ThemeMode::Light => LIGHT_ACCENT_DIM,
    }
}

/// Returns the current theme's border color.
pub fn border(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BORDER,
        ThemeMode::Light => LIGHT_BORDER,
    }
}

/// Returns the current theme's banner info background color.
pub fn banner_info_bg(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BANNER_INFO_BG,
        ThemeMode::Light => LIGHT_BANNER_INFO_BG,
    }
}

/// Returns the current theme's banner info text color.
pub fn banner_info_text(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BANNER_INFO_TEXT,
        ThemeMode::Light => LIGHT_BANNER_INFO_TEXT,
    }
}

/// Returns the current theme's banner info value color.
pub fn banner_info_value(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BANNER_INFO_VALUE,
        ThemeMode::Light => LIGHT_BANNER_INFO_VALUE,
    }
}

/// Returns the current theme's banner error background color.
pub fn banner_error_bg(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BANNER_ERROR_BG,
        ThemeMode::Light => LIGHT_BANNER_ERROR_BG,
    }
}

/// Returns the current theme's banner error text color.
pub fn banner_error_text(mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::Dark => BANNER_ERROR_TEXT,
        ThemeMode::Light => LIGHT_BANNER_ERROR_TEXT,
    }
}

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
pub fn apply_dark_theme(ctx: &egui::Context) {
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

/// Apply the light modern theme to the egui context.
pub fn apply_light_theme(ctx: &egui::Context) {
    let mut visuals = Visuals::light();

    visuals.panel_fill = LIGHT_BG_PRIMARY;
    visuals.window_fill = LIGHT_BG_SECONDARY;
    visuals.faint_bg_color = LIGHT_BG_SECONDARY;
    visuals.extreme_bg_color = Color32::from_rgb(220, 222, 230);

    visuals.widgets.noninteractive.bg_fill = LIGHT_BG_SECONDARY;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, LIGHT_TEXT_PRIMARY);
    visuals.widgets.noninteractive.corner_radius = CornerRadius::same(6);

    visuals.widgets.inactive.bg_fill = LIGHT_BG_SECONDARY;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, LIGHT_TEXT_SECONDARY);
    visuals.widgets.inactive.corner_radius = CornerRadius::same(6);

    visuals.widgets.hovered.bg_fill = LIGHT_BG_HOVER;
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, LIGHT_TEXT_PRIMARY);
    visuals.widgets.hovered.corner_radius = CornerRadius::same(6);

    visuals.widgets.active.bg_fill = LIGHT_ACCENT_DIM;
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.corner_radius = CornerRadius::same(6);

    visuals.selection.bg_fill = LIGHT_ACCENT_DIM;
    visuals.selection.stroke = Stroke::new(1.0, LIGHT_ACCENT);

    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.window_stroke = Stroke::new(1.0, LIGHT_BORDER);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.spacing.item_spacing = ITEM_SPACING;
    style.spacing.window_margin = egui::Margin::same(16);
    ctx.set_style(style);
}

/// Apply the theme based on the current theme mode.
pub fn apply_theme(ctx: &egui::Context, mode: ThemeMode) {
    match mode {
        ThemeMode::Dark => apply_dark_theme(ctx),
        ThemeMode::Light => apply_light_theme(ctx),
    }
}
