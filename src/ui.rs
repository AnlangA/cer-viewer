//! UI rendering for the certificate viewer.
//!
//! Contains the [`CertViewerApp`] struct that implements [`eframe::App`],
//! plus helpers for drawing the certificate field tree.

use crate::cert::{self, CertChain, CertField, ParsedCert, ValidityStatus};
use crate::document::{self, Document};
use crate::security::{is_potentially_sensitive, sensitive_copy_warning, SensitiveDataType};
use crate::theme;
use egui::{
    CollapsingHeader, Context, CornerRadius, Frame, Id, Key, KeyboardShortcut, Margin, RichText,
    ScrollArea, Stroke, Ui, Vec2,
};
use std::collections::HashMap;
use tracing::{info, warn};

// ── Keyboard shortcuts ──────────────────────────────────────────────

const OPEN_FILES_SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(egui::Modifiers::COMMAND, Key::O);
const CLOSE_TAB_SHORTCUT: KeyboardShortcut =
    KeyboardShortcut::new(egui::Modifiers::COMMAND, Key::W);

// ── Tab action for deferred UI updates ──────────────────────────────

/// Deferred tab actions to avoid mutability issues during UI rendering.
#[derive(Clone, Copy)]
enum TabAction {
    /// Switch to the tab at the given index.
    Select(usize),
    /// Close the tab at the given index.
    Close(usize),
}

/// View mode for certificate display.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    /// Show single certificate details.
    Details,
    /// Show certificate chain.
    Chain,
}

// ── Application state ──────────────────────────────────────────────

/// Main application state for the certificate viewer.
pub struct CertViewerApp {
    /// Currently loaded documents (certificates and CSRs, maintains insertion order).
    documents: Vec<Document>,
    /// Map from document ID string to index for O(1) dedup lookup.
    doc_index: HashMap<String, usize>,
    /// Index of the selected tab.
    selected_tab: usize,
    /// Current view mode (details or chain).
    view_mode: ViewMode,
    /// Error messages to display (collected from all file operations).
    error_msgs: Vec<String>,
    /// Info message to display, if any.
    info_msg: Option<String>,
    /// Whether the theme has been applied.
    theme_applied: bool,
    /// Cached clipboard instance.
    clipboard: Option<arboard::Clipboard>,
    /// Completed chain cache (with auto-downloaded intermediates).
    #[cfg(feature = "network")]
    completed_chain: Option<CertChain>,
    /// Receiver for background chain completion results.
    #[cfg(feature = "network")]
    chain_completion_rx: Option<std::sync::mpsc::Receiver<CertChain>>,
    /// Whether a chain completion download is in progress.
    #[cfg(feature = "network")]
    chain_completion_pending: bool,
    /// Cached chain before completion (rebuilt when certs change).
    #[cfg(feature = "network")]
    initial_chain: Option<CertChain>,
}

impl CertViewerApp {
    /// Create a new application with no documents loaded.
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self::setup_chinese_fonts(&cc.egui_ctx);

        let clipboard = match arboard::Clipboard::new() {
            Ok(cb) => Some(cb),
            Err(e) => {
                tracing::warn!("Failed to initialize clipboard: {}", e);
                None
            }
        };

        Self {
            documents: Vec::new(),
            doc_index: HashMap::new(),
            selected_tab: 0,
            view_mode: ViewMode::Details,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            clipboard,
            #[cfg(feature = "network")]
            completed_chain: None,
            #[cfg(feature = "network")]
            chain_completion_rx: None,
            #[cfg(feature = "network")]
            chain_completion_pending: false,
            #[cfg(feature = "network")]
            initial_chain: None,
        }
    }

    /// Setup Chinese font for rendering Chinese characters.
    fn setup_chinese_fonts(ctx: &egui::Context) {
        let mut fonts = egui::FontDefinitions::default();

        fonts.font_data.insert(
            "NotoSansSC".to_owned(),
            std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
                "../assets/NotoSansSC-Regular.ttf"
            ))),
        );

        fonts
            .families
            .entry(egui::FontFamily::Proportional)
            .or_default()
            .push("NotoSansSC".to_owned());

        fonts
            .families
            .entry(egui::FontFamily::Monospace)
            .or_default()
            .push("NotoSansSC".to_owned());

        ctx.set_fonts(fonts);
    }

    /// Load a document from raw bytes (auto-detects PEM/DER).
    /// Returns true if any new document was loaded.
    #[allow(dead_code)]
    pub fn load_certificate_bytes(&mut self, data: &[u8]) -> bool {
        let results = document::load_documents(data);
        let mut loaded = false;

        for result in &results {
            match result {
                Ok(doc) => {
                    let id_str = doc.id_str().to_string();
                    if let Some(existing_idx) = self.doc_index.get(&id_str) {
                        info!(id = %id_str, "Document already loaded, switching to tab");
                        self.selected_tab = *existing_idx;
                        self.show_info(format!("Already loaded: {}", doc.display_name()));
                        continue;
                    }

                    info!(name = %doc.display_name(), "Document loaded");
                    if !loaded {
                        self.error_msgs.clear();
                    }
                    loaded = true;
                    let idx = self.documents.len();
                    self.doc_index.insert(id_str, idx);
                    self.documents.push(doc.clone());
                    self.selected_tab = idx;
                }
                Err(e) => {
                    warn!(error = %e, "Failed to load document");
                    self.error_msgs.push(e.clone());
                }
            }
        }

        if loaded {
            self.invalidate_chain_cache();
        }
        loaded
    }

    /// Find a document by its ID string, returns the index if found.
    #[allow(dead_code)]
    fn find_document_by_id(&self, id_str: &str) -> Option<usize> {
        self.doc_index.get(id_str).copied()
    }

    /// Load documents from multiple files, supporting PEM certificate chains and CSRs.
    fn load_files(&mut self, paths: Vec<std::path::PathBuf>) {
        let mut loaded_count = 0;
        let mut skipped_count = 0;
        let mut errors: Vec<String> = Vec::new();
        let mut last_loaded_idx: Option<usize> = None;

        for path in &paths {
            match std::fs::read(path) {
                Ok(data) => {
                    let results = document::load_documents(&data);
                    for result in &results {
                        match result {
                            Ok(doc) => {
                                let id_str = doc.id_str().to_string();
                                if let Some(existing_idx) = self.doc_index.get(&id_str) {
                                    info!(
                                        id = %id_str,
                                        "Document already loaded from {:?}, skipping",
                                        path
                                    );
                                    last_loaded_idx = Some(*existing_idx);
                                    skipped_count += 1;
                                } else {
                                    info!(name = %doc.display_name(), "Document loaded from {:?}", path);
                                    let idx = self.documents.len();
                                    self.doc_index.insert(id_str, idx);
                                    self.documents.push(doc.clone());
                                    last_loaded_idx = Some(idx);
                                    loaded_count += 1;
                                }
                            }
                            Err(e) => {
                                let file_name = path
                                    .file_name()
                                    .and_then(|n| n.to_str())
                                    .unwrap_or("<invalid filename>");
                                errors.push(format!("Failed to parse {file_name}: {e}"));
                            }
                        }
                    }
                }
                Err(e) => {
                    let file_name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("<invalid filename>");
                    errors.push(format!("Failed to read {file_name}: {e}"));
                }
            }
        }

        // Switch to the last loaded or existing document
        if let Some(idx) = last_loaded_idx {
            self.selected_tab = idx;
            if loaded_count > 0 {
                self.error_msgs.clear();
                self.invalidate_chain_cache();
                self.reorder_docs();
            }
        }

        // Show info about results
        if loaded_count > 0 || skipped_count > 0 {
            let mut msg = String::new();
            if loaded_count > 0 {
                msg.push_str(&format!("Loaded {} document(s)", loaded_count));
            }
            if skipped_count > 0 {
                if !msg.is_empty() {
                    msg.push_str(", ");
                }
                msg.push_str(&format!("skipped {} duplicate(s)", skipped_count));
            }
            self.show_info(msg);
        }

        // Collect all errors
        self.error_msgs = errors;
    }

    /// Open a file dialog and load the selected files (supports multiple selection).
    fn open_file_dialog(&mut self) {
        let files = rfd::FileDialog::new()
            .set_title("Open Certificates / CSRs")
            .add_filter(
                "Certificates & CSRs",
                &["pem", "crt", "cer", "der", "cert", "csr"],
            )
            .add_filter("All Files", &["*"])
            .pick_files();

        if let Some(paths) = files {
            self.load_files(paths);
        }
    }

    /// Remove a document at the given index.
    fn remove_document(&mut self, index: usize) {
        if index < self.documents.len() {
            let name = self.documents[index].display_name().to_string();
            self.documents.remove(index);

            // Rebuild the index map since indices shifted
            self.rebuild_doc_index();
            self.invalidate_chain_cache();
            self.reorder_docs();

            self.show_info(format!("Closed: {}", name));
            if self.documents.is_empty() {
                self.selected_tab = 0;
            } else if self.selected_tab >= self.documents.len() {
                self.selected_tab = self.documents.len() - 1;
            }
        }
    }

    /// Clear all loaded documents.
    fn clear_all_documents(&mut self) {
        let count = self.documents.len();
        self.documents.clear();
        self.doc_index.clear();
        self.selected_tab = 0;
        self.error_msgs.clear();
        self.invalidate_chain_cache();
        self.show_info(format!("Cleared {} document(s)", count));
    }

    /// Rebuild the document index map after modifications.
    fn rebuild_doc_index(&mut self) {
        self.doc_index = self
            .documents
            .iter()
            .enumerate()
            .map(|(i, doc)| (doc.id_str().to_string(), i))
            .collect();
    }

    /// Check if a certificate at the given index is a leaf (end-entity) certificate.
    fn is_leaf_cert(&self, idx: usize) -> bool {
        if idx >= self.documents.len() {
            return false;
        }
        let doc = &self.documents[idx];
        let cert = match doc {
            Document::Certificate(c) => c,
            _ => return false,
        };
        let subject = &cert.subject;
        let is_self_signed = cert.issuer == *subject;
        if is_self_signed {
            return false;
        }
        // Leaf = no other cert lists this cert's subject as its issuer
        for (i, other_doc) in self.documents.iter().enumerate() {
            if i != idx {
                if let Document::Certificate(other) = other_doc {
                    if other.issuer == *subject {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Reorder documents so leaf certs are on the left, CSRs at the end.
    fn reorder_docs(&mut self) {
        let selected_id = self
            .documents
            .get(self.selected_tab)
            .map(|d| d.id_str().to_string());

        let all_docs: Vec<Document> = self.documents.drain(..).collect();

        // Determine leaf status for each cert document
        let is_leaf_vec: Vec<bool> = all_docs
            .iter()
            .enumerate()
            .map(|(i, doc)| {
                let cert = match doc {
                    Document::Certificate(c) => c,
                    _ => return false,
                };
                if cert.issuer == cert.subject {
                    return false;
                }
                let mut is_issuer = false;
                for (j, other_doc) in all_docs.iter().enumerate() {
                    if j != i {
                        if let Document::Certificate(other) = other_doc {
                            if other.issuer == cert.subject {
                                is_issuer = true;
                                break;
                            }
                        }
                    }
                }
                !is_issuer
            })
            .collect();

        // Partition: leaf certs, non-leaf certs, CSRs
        let mut leafs: Vec<Document> = Vec::new();
        let mut others: Vec<Document> = Vec::new();
        let mut csrs: Vec<Document> = Vec::new();

        for (doc, is_leaf) in all_docs.into_iter().zip(is_leaf_vec) {
            if doc.is_csr() {
                csrs.push(doc);
            } else if is_leaf {
                leafs.push(doc);
            } else {
                others.push(doc);
            }
        }

        self.documents = leafs;
        self.documents.extend(others);
        self.documents.extend(csrs);
        self.rebuild_doc_index();

        // Restore selected tab
        if let Some(ref id) = selected_id {
            if let Some(&new_idx) = self.doc_index.get(id) {
                self.selected_tab = new_idx;
            }
        }
    }

    /// Show an info message.
    fn show_info(&mut self, msg: String) {
        self.info_msg = Some(msg);
    }

    /// Invalidate the completed chain cache and start a new background chain
    /// completion if the chain is incomplete.
    fn invalidate_chain_cache(&mut self) {
        #[cfg(feature = "network")]
        {
            self.completed_chain = None;
            self.initial_chain = None;
            self.chain_completion_rx = None;
            self.chain_completion_pending = false;

            // Only build chains from certificates (not CSRs)
            let certs: Vec<ParsedCert> = self
                .documents
                .iter()
                .filter_map(|d| match d {
                    Document::Certificate(c) => Some(c.clone()),
                    _ => None,
                })
                .collect();

            if certs.is_empty() || self.chain_completion_pending {
                return;
            }
            let chain = CertChain::build(certs.clone());
            if matches!(
                chain.validation_status,
                cert::ChainValidationStatus::Incomplete { .. }
            ) {
                let certs_clone = certs;
                let (tx, rx) = std::sync::mpsc::channel();
                self.chain_completion_rx = Some(rx);
                self.chain_completion_pending = true;

                std::thread::spawn(move || {
                    let completed = CertChain::build(certs_clone).complete_chain();
                    let _ = tx.send(completed);
                });
            }
        }
    }

    /// Get only the certificates from loaded documents (for chain building).
    fn get_certs(&self) -> Vec<ParsedCert> {
        self.documents
            .iter()
            .filter_map(|d| match d {
                Document::Certificate(c) => Some(c.clone()),
                _ => None,
            })
            .collect()
    }

    /// Copy text to clipboard using cached clipboard instance.
    fn copy_to_clipboard(&mut self, text: String) {
        let data_type = SensitiveDataType::detect("clipboard", Some(&text));
        let is_sensitive = data_type.is_some();

        if let Some(clipboard) = &mut self.clipboard {
            match clipboard.set_text(&text) {
                Ok(()) => {
                    if is_sensitive {
                        let warning = sensitive_copy_warning(data_type.unwrap().description());
                        self.show_info(warning);
                        warn!(
                            "Copied sensitive data to clipboard: {} chars, type: {:?}",
                            text.len(),
                            data_type
                        );
                    } else {
                        self.show_info("Copied to clipboard".to_string());
                        info!("Copied to clipboard: {} chars", text.len());
                    }
                    return;
                }
                Err(e) => {
                    warn!("Failed to copy with cached clipboard: {}", e);
                }
            }
        }

        match arboard::Clipboard::new() {
            Ok(mut clipboard) => match clipboard.set_text(&text) {
                Ok(()) => {
                    self.clipboard = Some(clipboard);
                    if is_sensitive {
                        let warning = sensitive_copy_warning(data_type.unwrap().description());
                        self.show_info(warning);
                        warn!(
                            "Copied sensitive data to clipboard: {} chars, type: {:?}",
                            text.len(),
                            data_type
                        );
                    } else {
                        self.show_info("Copied to clipboard".to_string());
                        info!("Copied to clipboard: {} chars", text.len());
                    }
                }
                Err(e) => {
                    warn!("Failed to copy to clipboard: {}", e);
                    self.error_msgs.push(format!("Failed to copy: {}", e));
                }
            },
            Err(e) => {
                warn!("Failed to access clipboard: {}", e);
            }
        }
    }

    /// Handle keyboard shortcuts.
    fn handle_shortcuts(&mut self, ctx: &Context) {
        if ctx.input_mut(|i| i.consume_shortcut(&OPEN_FILES_SHORTCUT)) {
            self.open_file_dialog();
        }

        if ctx.input_mut(|i| i.consume_shortcut(&CLOSE_TAB_SHORTCUT)) && !self.documents.is_empty()
        {
            self.remove_document(self.selected_tab);
        }
    }

    /// Handle drag and drop.
    fn handle_drag_drop(&mut self, ctx: &Context) {
        let paths: Vec<std::path::PathBuf> = ctx.input_mut(|i| {
            i.raw
                .dropped_files
                .drain(..)
                .filter_map(|f| f.path)
                .collect()
        });

        if !paths.is_empty() {
            self.load_files(paths);
        }
    }
}

impl eframe::App for CertViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            theme::apply_theme(ctx);
            self.theme_applied = true;
        }

        self.handle_shortcuts(ctx);
        self.handle_drag_drop(ctx);

        // Poll background chain completion result every frame
        #[cfg(feature = "network")]
        {
            let mut completed_chain_result = None;
            if let Some(ref rx) = self.chain_completion_rx {
                if let Ok(completed) = rx.try_recv() {
                    completed_chain_result = Some(completed);
                }
            }
            if let Some(completed) = completed_chain_result {
                let original_ids: std::collections::HashSet<cert::CertId> = self
                    .documents
                    .iter()
                    .filter_map(|d| match d {
                        Document::Certificate(c) => Some(c.id.clone()),
                        _ => None,
                    })
                    .collect();
                let new_certs = completed.downloaded_certs(&original_ids);
                let has_new = !new_certs.is_empty();
                for new_cert in new_certs {
                    let idx = self.documents.len();
                    self.doc_index.insert(new_cert.id.0.clone(), idx);
                    self.documents.push(Document::Certificate(new_cert));
                }
                self.completed_chain = Some(completed);
                self.chain_completion_rx = None;
                self.chain_completion_pending = false;
                if has_new {
                    self.rebuild_doc_index();
                    self.reorder_docs();
                }
            }
        }

        // ── Top panel: toolbar ─────────────────────────────────
        egui::TopBottomPanel::top("toolbar")
            .frame(
                Frame::new()
                    .fill(theme::BG_HEADER)
                    .inner_margin(Margin::symmetric(12, 8))
                    .stroke(Stroke::new(1.0, theme::BORDER)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Certificate Viewer")
                            .size(theme::FONT_TITLE)
                            .color(theme::ACCENT)
                            .strong(),
                    );

                    ui.add_space(16.0);
                    ui.separator();
                    ui.add_space(8.0);

                    let btn =
                        egui::Button::new(RichText::new("Open Files...").size(theme::FONT_BODY))
                            .corner_radius(CornerRadius::same(4));
                    if ui.add(btn).clicked() {
                        self.open_file_dialog();
                    }

                    if !self.documents.is_empty() {
                        let clear_btn =
                            egui::Button::new(RichText::new("Clear All").size(theme::FONT_BODY))
                                .corner_radius(CornerRadius::same(4));
                        if ui.add(clear_btn).clicked() {
                            self.clear_all_documents();
                        }
                    }

                    ui.add_space(8.0);
                    ui.separator();
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new("Ctrl+O: Open | Ctrl+W: Close")
                            .size(11.0)
                            .color(theme::TEXT_SECONDARY),
                    );
                });

                // Tab bar for documents
                if !self.documents.is_empty() {
                    ui.add_space(4.0);

                    let tab_data: Vec<(usize, String, bool, bool, Option<ValidityStatus>)> = self
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
                                Document::Certificate(c) => Some(c.validity_status),
                                _ => None,
                            };
                            (i, label, i == self.selected_tab, doc.is_csr(), validity)
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
                                            theme::BG_SECONDARY
                                        } else {
                                            egui::Color32::TRANSPARENT
                                        })
                                        .corner_radius(CornerRadius::same(4))
                                        .inner_margin(Margin::symmetric(8, 4))
                                        .stroke(if *is_selected {
                                            Stroke::new(1.0, theme::ACCENT)
                                        } else {
                                            Stroke::new(1.0, theme::BORDER)
                                        });

                                    tab_frame.show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.spacing_mut().item_spacing = Vec2::new(6.0, 0.0);

                                            // Indicator dot
                                            let indicator_color = if *is_csr {
                                                theme::CSR_INDICATOR
                                            } else if let Some(validity) = validity {
                                                if self.is_leaf_cert(*i) {
                                                    theme::LEAF_INDICATOR
                                                } else {
                                                    theme::validity_color(*validity)
                                                }
                                            } else {
                                                theme::TEXT_SECONDARY
                                            };
                                            ui.label(RichText::new("*").color(indicator_color));

                                            let text = RichText::new(label)
                                                .size(theme::FONT_BODY)
                                                .color(if *is_selected {
                                                    theme::TEXT_PRIMARY
                                                } else {
                                                    theme::TEXT_SECONDARY
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

                                    ui.add_space(2.0);
                                }
                            });
                        });

                    if let Some(act) = action {
                        match act {
                            TabAction::Select(i) => self.selected_tab = i,
                            TabAction::Close(i) => self.remove_document(i),
                        }
                    }
                }
            });

        // ── Central panel: document content ─────────────────
        egui::CentralPanel::default()
            .frame(
                Frame::new()
                    .fill(theme::BG_PRIMARY)
                    .inner_margin(Margin::same(16)),
            )
            .show(ctx, |ui| {
                // Info banner
                if let Some(ref msg) = self.info_msg {
                    Frame::new()
                        .fill(theme::BANNER_INFO_BG)
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("[i]").color(theme::BANNER_INFO_TEXT));
                                ui.label(RichText::new(msg).color(theme::BANNER_INFO_VALUE));
                            });
                        });
                    ui.add_space(8.0);
                    self.info_msg = None;
                }

                // Error banners
                for msg in &self.error_msgs {
                    Frame::new()
                        .fill(theme::BANNER_ERROR_BG)
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!("[!] {msg}")).color(theme::BANNER_ERROR_TEXT),
                            );
                        });
                    ui.add_space(8.0);
                }

                if self.documents.is_empty() {
                    draw_empty_state(ui);
                } else {
                    let selected_doc = self.documents.get(self.selected_tab);
                    let has_any_cert = self
                        .documents
                        .iter()
                        .any(|d| matches!(d, Document::Certificate(_)));

                    // View mode switcher (only for certificates)
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("View:").color(theme::TEXT_LABEL));
                        let details_btn = egui::Button::new(
                            RichText::new("Document Details").size(theme::FONT_BODY),
                        )
                        .corner_radius(CornerRadius::same(4))
                        .fill(if self.view_mode == ViewMode::Details {
                            theme::ACCENT
                        } else {
                            egui::Color32::TRANSPARENT
                        });
                        if ui.add(details_btn).clicked() {
                            self.view_mode = ViewMode::Details;
                        }

                        // Show Chain View button when the selected document is a certificate
                        // and there is at least one certificate loaded
                        let chain_enabled = has_any_cert
                            && selected_doc.map(|d| !d.is_csr()).unwrap_or(false);

                        if chain_enabled {
                            let chain_btn = egui::Button::new(
                                RichText::new("Chain View").size(theme::FONT_BODY),
                            )
                            .corner_radius(CornerRadius::same(4))
                            .fill(if self.view_mode == ViewMode::Chain {
                                theme::ACCENT
                            } else {
                                egui::Color32::TRANSPARENT
                            });

                            if ui.add(chain_btn).clicked() {
                                self.view_mode = ViewMode::Chain;
                            }
                        }
                    });
                    ui.add_space(8.0);

                    match self.view_mode {
                        ViewMode::Details => {
                            if let Some(doc) = selected_doc {
                                let mut to_copy: Option<String> = None;
                                draw_document(ui, doc, &mut |text| {
                                    to_copy = Some(text);
                                });

                                if let Some(text) = to_copy {
                                    self.copy_to_clipboard(text);
                                }
                            }
                        }
                        ViewMode::Chain => {
                            #[cfg(feature = "network")]
                            {
                                let certs = self.get_certs();
                                let chain = self.completed_chain.clone().unwrap_or_else(|| {
                                    self.initial_chain
                                        .get_or_insert_with(|| CertChain::build(certs))
                                        .clone()
                                });

                                if self.chain_completion_pending {
                                    ui.add_space(8.0);
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            RichText::new("Downloading missing certificates...")
                                                .size(theme::FONT_BODY)
                                                .color(theme::TEXT_SECONDARY),
                                        );
                                        ui.spinner();
                                    });
                                }

                                draw_chain(ui, &chain);
                            }
                            #[cfg(not(feature = "network"))]
                            {
                                let certs = self.get_certs();
                                let chain = CertChain::build(certs);
                                draw_chain(ui, &chain);
                            }
                        }
                    }
                }
            });
    }
}

// ── Empty state ────────────────────────────────────────────────────

fn draw_empty_state(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(80.0);
        ui.label(
            RichText::new("No certificate or CSR loaded")
                .size(22.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(12.0);
        ui.label(
            RichText::new("Click \"Open Files...\" or drag & drop certificates or CSRs here")
                .size(14.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("Supported formats: PEM, DER, CRT, CER, CSR")
                .size(12.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(20.0);
        ui.label(
            RichText::new("Keyboard shortcuts:")
                .size(12.0)
                .color(theme::TEXT_SECONDARY),
        );
        ui.add_space(4.0);
        ui.label(
            RichText::new("Ctrl+O: Open files  |  Ctrl+W: Close tab")
                .size(11.0)
                .color(theme::TEXT_SECONDARY),
        );
    });
}

// ── Document rendering ──────────────────────────────────────────────

/// Draw a document (certificate or CSR) card and field tree.
fn draw_document<F>(ui: &mut Ui, doc: &Document, on_copy: &mut F)
where
    F: FnMut(String),
{
    match doc {
        Document::Certificate(cert) => draw_certificate(ui, cert, on_copy),
        Document::Csr(csr) => draw_csr(ui, csr, on_copy),
    }
}

fn draw_certificate<F>(ui: &mut Ui, cert: &ParsedCert, on_copy: &mut F)
where
    F: FnMut(String),
{
    let status_text = theme::validity_text(cert.validity_status);
    let status_color = theme::validity_color(cert.validity_status);

    Frame::new()
        .fill(theme::BG_SECONDARY)
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, theme::BORDER))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&cert.display_name)
                            .size(theme::FONT_TITLE)
                            .color(theme::TEXT_PRIMARY)
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
                            .color(theme::TEXT_SECONDARY),
                    );
                    ui.label(
                        RichText::new(" -> ")
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_SECONDARY),
                    );
                    ui.label(
                        RichText::new(&cert.not_after)
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_SECONDARY),
                    );
                });
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
                draw_field(ui, field, 0, on_copy);
            }
        });
}

fn draw_csr<F>(ui: &mut Ui, csr: &crate::formats::csr::ParsedCsr, on_copy: &mut F)
where
    F: FnMut(String),
{
    Frame::new()
        .fill(theme::BG_SECONDARY)
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, theme::BORDER))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&csr.display_name)
                            .size(theme::FONT_TITLE)
                            .color(theme::TEXT_PRIMARY)
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
                            .color(theme::TEXT_LABEL),
                    );
                    ui.label(
                        RichText::new(&csr.signature_algorithm)
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_VALUE),
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
                draw_field(ui, field, 0, on_copy);
            }
        });
}

/// Draw certificate chain view.
fn draw_chain(ui: &mut Ui, chain: &CertChain) {
    use crate::cert::ChainValidationStatus;

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
        .fill(theme::BG_SECONDARY)
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin::same(12))
        .stroke(Stroke::new(1.0, theme::BORDER))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Certificate Chain")
                            .size(theme::FONT_TITLE)
                            .color(theme::TEXT_PRIMARY)
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
                        .color(theme::TEXT_SECONDARY),
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
                draw_chain_cert(ui, chain_cert, i, chain.certificates.len());
                ui.add_space(8.0);
            }
        });
}

/// Draw a single certificate in the chain view.
fn draw_chain_cert(ui: &mut Ui, chain_cert: &crate::cert::ChainCert, index: usize, total: usize) {
    use crate::cert::ChainPosition;

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

    use crate::cert::SignatureStatus;

    let border_color = match chain_cert.signature_status {
        SignatureStatus::Valid => egui::Color32::from_rgb(100, 200, 100),
        SignatureStatus::Invalid => egui::Color32::RED,
        SignatureStatus::Unknown => egui::Color32::from_rgb(200, 180, 50),
    };

    Frame::new()
        .fill(theme::BG_SECONDARY)
        .corner_radius(CornerRadius::same(4))
        .inner_margin(Margin::same(10))
        .stroke(Stroke::new(2.0, border_color))
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
                            .color(theme::TEXT_SECONDARY),
                    );
                });

                ui.add_space(4.0);

                // Certificate name
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(&chain_cert.cert.display_name)
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_PRIMARY)
                            .strong(),
                    );
                });

                ui.add_space(4.0);

                // Subject
                ui.label(
                    RichText::new("Subject:")
                        .size(theme::FONT_BODY)
                        .color(theme::TEXT_LABEL),
                );
                ui.label(
                    RichText::new(&chain_cert.cert.subject)
                        .size(theme::FONT_BODY)
                        .color(theme::TEXT_VALUE),
                );

                // Issuer
                ui.label(
                    RichText::new("Issuer:")
                        .size(theme::FONT_BODY)
                        .color(theme::TEXT_LABEL),
                );
                ui.label(
                    RichText::new(&chain_cert.cert.issuer)
                        .size(theme::FONT_BODY)
                        .color(theme::TEXT_VALUE),
                );

                // Validity
                let validity_color = theme::validity_color(chain_cert.cert.validity_status);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Validity:")
                            .size(theme::FONT_BODY)
                            .color(theme::TEXT_LABEL),
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
                            .color(theme::TEXT_LABEL),
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

fn draw_field<F>(ui: &mut Ui, field: &CertField, depth: usize, on_copy: &mut F)
where
    F: FnMut(String),
{
    let id = Id::new(&field.label)
        .with(depth)
        .with(field.value.as_deref().unwrap_or("").get(..20).unwrap_or(""));

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

        Frame::new()
            .fill(if is_root {
                theme::BG_SECONDARY
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
                Stroke::new(1.0, theme::BORDER)
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
                    .color(if depth == 0 {
                        theme::TEXT_PRIMARY
                    } else {
                        theme::TEXT_LABEL
                    })
                    .strong();

                CollapsingHeader::new(header)
                    .id_salt(id)
                    .default_open(is_root && !field.label.contains("Signature Value"))
                    .show(ui, |ui| {
                        if let Some(ref val) = field.value {
                            ui.horizontal_wrapped(|ui| {
                                ui.add_space(8.0);
                                ui.label(
                                    RichText::new(val)
                                        .font(theme::mono_font())
                                        .color(theme::TEXT_VALUE),
                                );
                            });
                            ui.add_space(2.0);
                        }
                        for child in &field.children {
                            draw_field(ui, child, depth + 1, on_copy);
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
                    .color(theme::TEXT_LABEL),
            );
            if let Some(ref val) = field.value {
                ui.label(
                    RichText::new(" : ")
                        .color(theme::TEXT_SECONDARY)
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
                        .color(theme::TEXT_VALUE),
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

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_app() -> CertViewerApp {
        CertViewerApp {
            documents: Vec::new(),
            doc_index: HashMap::new(),
            selected_tab: 0,
            view_mode: ViewMode::Details,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            clipboard: None,
            #[cfg(feature = "network")]
            completed_chain: None,
            #[cfg(feature = "network")]
            chain_completion_rx: None,
            #[cfg(feature = "network")]
            chain_completion_pending: false,
            #[cfg(feature = "network")]
            initial_chain: None,
        }
    }

    #[test]
    fn test_app_initial_state() {
        let app = test_app();
        assert!(app.documents.is_empty());
        assert_eq!(app.selected_tab, 0);
        assert!(app.error_msgs.is_empty());
    }

    #[test]
    fn test_load_valid_certificate() {
        let mut app = test_app();
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);
        assert_eq!(app.documents.len(), 1);
        assert!(app.error_msgs.is_empty());
        assert_eq!(app.selected_tab, 0);
    }

    #[test]
    fn test_load_invalid_certificate_sets_error() {
        let mut app = test_app();
        app.load_certificate_bytes(b"not a certificate");
        assert!(app.documents.is_empty());
        assert!(!app.error_msgs.is_empty());
    }

    #[test]
    fn test_load_duplicate_certificate() {
        let mut app = test_app();
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);
        assert_eq!(app.documents.len(), 1);
        assert_eq!(app.selected_tab, 0);

        app.load_certificate_bytes(pem);
        assert_eq!(app.documents.len(), 1);
        assert_eq!(app.selected_tab, 0);
    }

    #[test]
    fn test_load_csr() {
        let mut app = test_app();
        let csr = include_bytes!("../assets/test.csr");
        app.load_certificate_bytes(csr);
        assert_eq!(app.documents.len(), 1);
        assert!(app.error_msgs.is_empty());
        assert!(app.documents[0].is_csr());
    }

    #[test]
    fn test_load_csr_with_extensions() {
        let mut app = test_app();
        let csr = include_bytes!("../assets/test_with_exts.csr");
        app.load_certificate_bytes(csr);
        assert_eq!(app.documents.len(), 1);
        assert!(app.documents[0].is_csr());
        // Should have Attributes field
        let labels: Vec<&str> = app.documents[0]
            .fields()
            .iter()
            .map(|f| f.label.as_str())
            .collect();
        assert!(labels.contains(&"Attributes"));
    }

    #[test]
    fn test_validity_status_display() {
        let mut app = test_app();
        let pem = include_bytes!("../assets/baidu.com.pem");
        app.load_certificate_bytes(pem);

        let doc = &app.documents[0];
        match doc {
            Document::Certificate(cert) => {
                assert!(matches!(
                    cert.validity_status,
                    ValidityStatus::Valid | ValidityStatus::Expired | ValidityStatus::NotYetValid
                ));
            }
            _ => panic!("Expected certificate document"),
        }
    }
}
