//! UI rendering for the certificate viewer.
//!
//! Contains the [`CertViewerApp`] struct that implements [`eframe::App`],
//! plus helpers for drawing the certificate field tree.

mod app;
mod chain_view;
mod details_view;
mod diff_view;
mod empty_state;
mod field_tree;
mod generate_dialog;
mod password_dialog;
mod tab_bar;
mod toolbar;

pub use app::CertViewerApp;
