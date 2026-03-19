//! Main application state and business logic for the certificate viewer.

use crate::cert::{self, CertChain, ParsedCert};
use crate::document::{self, Document};
use crate::security::{sensitive_copy_warning, SensitiveDataType};
use crate::theme::{self, ThemeMode};
use crate::ui::toolbar::{CLOSE_TAB_SHORTCUT, OPEN_FILES_SHORTCUT};
use egui::{Context, CornerRadius, Frame, Margin, RichText};
use std::collections::HashMap;
use tracing::{info, warn};

/// Result of background file loading.
pub(crate) struct FileLoadResult {
    /// Successfully parsed documents.
    pub documents: Vec<Document>,
    /// Error messages from file operations.
    pub errors: Vec<String>,
    /// First file path (used for recent files list).
    pub file_path: Option<std::path::PathBuf>,
}

/// View mode for certificate display.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ViewMode {
    /// Show single certificate details.
    Details,
    /// Show certificate chain.
    Chain,
}

/// Maximum number of recent files to remember.
const MAX_RECENT_FILES: usize = 10;

/// Path to the recent files config file.
fn recent_files_path() -> Option<std::path::PathBuf> {
    let proj_dirs = directories::ProjectDirs::from("", "", "cer-viewer")?;
    Some(proj_dirs.data_dir().join("recent_files.json"))
}

/// Load recent files list from disk.
fn load_recent_files_from_disk() -> Vec<String> {
    let path = match recent_files_path() {
        Some(p) => p,
        None => return Vec::new(),
    };

    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Save recent files list to disk.
fn save_recent_files_to_disk(recent_files: &[String]) {
    let path = match recent_files_path() {
        Some(p) => p,
        None => return,
    };

    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let _ = std::fs::write(
        &path,
        serde_json::to_string(recent_files).unwrap_or_default(),
    );
}

// ── Application state ──────────────────────────────────────────────

/// Main application state for the certificate viewer.
pub struct CertViewerApp {
    /// Currently loaded documents (certificates and CSRs, maintains insertion order).
    pub(crate) documents: Vec<Document>,
    /// Map from document ID string to index for O(1) dedup lookup.
    pub(crate) doc_index: HashMap<String, usize>,
    /// Index of the selected tab.
    pub(crate) selected_tab: usize,
    /// Current view mode (details or chain).
    pub(crate) view_mode: ViewMode,
    /// Error messages to display (collected from all file operations).
    pub(crate) error_msgs: Vec<String>,
    /// Info message to display, if any.
    pub(crate) info_msg: Option<String>,
    /// Whether the theme has been applied.
    pub(crate) theme_applied: bool,
    /// Current theme mode (dark or light).
    pub(crate) theme_mode: ThemeMode,
    /// Cached clipboard instance.
    pub(crate) clipboard: Option<arboard::Clipboard>,
    /// Recent files list (max 10 entries).
    pub(crate) recent_files: Vec<String>,
    /// Completed chain cache (with auto-downloaded intermediates).
    #[cfg(feature = "network")]
    pub(crate) completed_chain: Option<CertChain>,
    /// Receiver for background chain completion results.
    #[cfg(feature = "network")]
    pub(crate) chain_completion_rx: Option<std::sync::mpsc::Receiver<CertChain>>,
    /// Whether a chain completion download is in progress.
    #[cfg(feature = "network")]
    pub(crate) chain_completion_pending: bool,
    /// Cached chain before completion (rebuilt when certs change).
    #[cfg(feature = "network")]
    pub(crate) initial_chain: Option<CertChain>,
    /// Whether file loading is in progress.
    pub(crate) loading_in_progress: bool,
    /// Receiver for background file loading results.
    pub(crate) file_load_rx: Option<std::sync::mpsc::Receiver<FileLoadResult>>,
    /// Search filter for certificate fields.
    pub(crate) search_filter: String,
    /// Persisted application configuration.
    pub(crate) config: crate::config::Config,
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

        let recent_files = load_recent_files_from_disk();

        let config = crate::config::Config::load();
        let theme_mode = if config.theme == "light" {
            ThemeMode::Light
        } else {
            ThemeMode::Dark
        };

        Self {
            documents: Vec::new(),
            doc_index: HashMap::new(),
            selected_tab: 0,
            view_mode: ViewMode::Details,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            theme_mode,
            clipboard,
            recent_files,
            #[cfg(feature = "network")]
            completed_chain: None,
            #[cfg(feature = "network")]
            chain_completion_rx: None,
            #[cfg(feature = "network")]
            chain_completion_pending: false,
            #[cfg(feature = "network")]
            initial_chain: None,
            loading_in_progress: false,
            file_load_rx: None,
            search_filter: String::new(),
            config,
        }
    }

    /// Setup Chinese font for rendering Chinese characters.
    fn setup_chinese_fonts(ctx: &egui::Context) {
        let mut fonts = egui::FontDefinitions::default();

        fonts.font_data.insert(
            "NotoSansSC".to_owned(),
            std::sync::Arc::new(egui::FontData::from_static(include_bytes!(
                "../../assets/NotoSansSC-Regular.ttf"
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

    /// Toggle between dark and light themes.
    pub(crate) fn toggle_theme(&mut self) {
        self.theme_mode = match self.theme_mode {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
        };
        self.config.theme = match self.theme_mode {
            ThemeMode::Dark => "dark",
            ThemeMode::Light => "light",
        }
        .to_string();
        self.config.save();
        self.theme_applied = false;
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

    /// Add a path to the recent files list.
    fn add_to_recent(&mut self, path: &str) {
        let path_str = path.to_string();
        // Remove existing entry if present, then push to front
        self.recent_files.retain(|p| p != &path_str);
        self.recent_files.insert(0, path_str);
        // Keep only the most recent entries
        self.recent_files.truncate(MAX_RECENT_FILES);
        save_recent_files_to_disk(&self.recent_files);
    }

    /// Load documents from multiple files, supporting PEM certificate chains and CSRs.
    pub(crate) fn load_files(&mut self, paths: Vec<std::path::PathBuf>) {
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

                    // Add successfully loaded files to recent list
                    if results.iter().any(|r| r.is_ok()) {
                        if let Some(path_str) = path.to_str() {
                            self.add_to_recent(path_str);
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

    /// Load documents from multiple files in a background thread to prevent UI freezes.
    /// Results are sent via a channel and polled in `update()`.
    pub(crate) fn load_files_async(&mut self, paths: Vec<std::path::PathBuf>) {
        let (tx, rx) = std::sync::mpsc::channel();
        self.file_load_rx = Some(rx);
        self.loading_in_progress = true;

        std::thread::spawn(move || {
            let mut documents: Vec<Document> = Vec::new();
            let mut errors: Vec<String> = Vec::new();
            let mut file_path: Option<std::path::PathBuf> = None;

            for path in &paths {
                match std::fs::read(path) {
                    Ok(data) => {
                        let results = document::load_documents(&data);
                        for result in &results {
                            match result {
                                Ok(doc) => documents.push(doc.clone()),
                                Err(e) => {
                                    let file_name = path
                                        .file_name()
                                        .and_then(|n| n.to_str())
                                        .unwrap_or("<invalid filename>");
                                    errors.push(format!("Failed to parse {file_name}: {e}"));
                                }
                            }
                        }
                        // Track first path that produced at least one document
                        if results.iter().any(|r| r.is_ok()) && file_path.is_none() {
                            file_path = Some(path.clone());
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

            let result = FileLoadResult {
                documents,
                errors,
                file_path,
            };
            let _ = tx.send(result);
        });
    }

    /// Process results from a completed background file load.
    fn process_file_load_result(&mut self, result: FileLoadResult) {
        let mut loaded_count = 0;
        let mut skipped_count = 0;
        let mut last_loaded_idx: Option<usize> = None;

        for doc in result.documents {
            let id_str = doc.id_str().to_string();
            if let Some(existing_idx) = self.doc_index.get(&id_str) {
                info!(id = %id_str, "Document already loaded, skipping");
                last_loaded_idx = Some(*existing_idx);
                skipped_count += 1;
            } else {
                info!(name = %doc.display_name(), "Document loaded");
                let idx = self.documents.len();
                self.doc_index.insert(id_str, idx);
                self.documents.push(doc);
                last_loaded_idx = Some(idx);
                loaded_count += 1;
            }
        }

        if let Some(idx) = last_loaded_idx {
            self.selected_tab = idx;
            if loaded_count > 0 {
                self.error_msgs.clear();
                self.invalidate_chain_cache();
                self.reorder_docs();
            }
        }

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

        self.error_msgs = result.errors;

        // Add to recent files on the main thread
        if let Some(ref path) = result.file_path {
            if let Some(path_str) = path.to_str() {
                self.add_to_recent(path_str);
            }
        }
    }

    /// Open a file dialog and load the selected files (supports multiple selection).
    pub(crate) fn open_file_dialog(&mut self) {
        let files = rfd::FileDialog::new()
            .set_title("Open Certificates / CSRs")
            .add_filter(
                "Certificates & CSRs",
                &["pem", "crt", "cer", "der", "cert", "csr"],
            )
            .add_filter("All Files", &["*"])
            .pick_files();

        if let Some(paths) = files {
            self.load_files_async(paths);
        }
    }

    /// Remove a document at the given index.
    pub(crate) fn remove_document(&mut self, index: usize) {
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
    pub(crate) fn clear_all_documents(&mut self) {
        let count = self.documents.len();
        self.documents.clear();
        self.doc_index.clear();
        self.selected_tab = 0;
        self.error_msgs.clear();
        self.invalidate_chain_cache();
        self.show_info(format!("Cleared {} document(s)", count));
    }

    /// Rebuild the document index map after modifications.
    pub(crate) fn rebuild_doc_index(&mut self) {
        self.doc_index = self
            .documents
            .iter()
            .enumerate()
            .map(|(i, doc)| (doc.id_str().to_string(), i))
            .collect();
    }

    /// Check if a certificate at the given index is a leaf (end-entity) certificate.
    pub(crate) fn is_leaf_cert(&self, idx: usize) -> bool {
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
    pub(crate) fn reorder_docs(&mut self) {
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
    pub(crate) fn show_info(&mut self, msg: String) {
        self.info_msg = Some(msg);
    }

    /// Invalidate the completed chain cache and start a new background chain
    /// completion if the chain is incomplete.
    pub(crate) fn invalidate_chain_cache(&mut self) {
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
    pub(crate) fn get_certs(&self) -> Vec<ParsedCert> {
        self.documents
            .iter()
            .filter_map(|d| match d {
                Document::Certificate(c) => Some(c.clone()),
                _ => None,
            })
            .collect()
    }

    /// Copy text to clipboard using cached clipboard instance.
    pub(crate) fn copy_to_clipboard(&mut self, text: String) {
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
            self.load_files_async(paths);
        }
    }
}

impl eframe::App for CertViewerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            theme::apply_theme(ctx, self.theme_mode);
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

        // Poll background file load result every frame
        {
            let mut file_load_result = None;
            if let Some(ref rx) = self.file_load_rx {
                if let Ok(result) = rx.try_recv() {
                    file_load_result = Some(result);
                }
            }
            if let Some(result) = file_load_result {
                self.process_file_load_result(result);
                self.loading_in_progress = false;
                self.file_load_rx = None;
            }
        }

        let theme_mode = self.theme_mode;

        // ── Top panel: toolbar ─────────────────────────────────
        crate::ui::toolbar::draw_toolbar(ctx, self);

        // ── Central panel: document content ─────────────────
        let bg_primary = theme::bg_primary(theme_mode);
        let banner_info_bg = theme::banner_info_bg(theme_mode);
        let banner_info_text = theme::banner_info_text(theme_mode);
        let banner_info_value = theme::banner_info_value(theme_mode);
        let banner_error_bg = theme::banner_error_bg(theme_mode);
        let banner_error_text = theme::banner_error_text(theme_mode);
        let accent = theme::accent(theme_mode);
        let text_label = theme::text_label(theme_mode);
        let text_secondary = theme::text_secondary(theme_mode);

        egui::CentralPanel::default()
            .frame(Frame::new().fill(bg_primary).inner_margin(Margin::same(16)))
            .show(ctx, |ui| {
                // Info banner
                if let Some(ref msg) = self.info_msg {
                    Frame::new()
                        .fill(banner_info_bg)
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("[i]").color(banner_info_text));
                                ui.label(RichText::new(msg).color(banner_info_value));
                            });
                        });
                    ui.add_space(8.0);
                    self.info_msg = None;
                }

                // Error banners
                for msg in &self.error_msgs {
                    Frame::new()
                        .fill(banner_error_bg)
                        .corner_radius(CornerRadius::same(4))
                        .inner_margin(Margin::same(10))
                        .show(ui, |ui| {
                            ui.label(RichText::new(format!("[!] {msg}")).color(banner_error_text));
                        });
                    ui.add_space(8.0);
                }

                // Loading indicator
                if self.loading_in_progress {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new("Loading files...").color(text_secondary));
                    });
                    ui.add_space(4.0);
                }

                if self.documents.is_empty() {
                    crate::ui::empty_state::draw_empty_state(ui, theme_mode, &mut || {
                        self.open_file_dialog();
                    });
                } else {
                    let selected_doc = self.documents.get(self.selected_tab);
                    let has_any_cert = self
                        .documents
                        .iter()
                        .any(|d| matches!(d, Document::Certificate(_)));

                    // View mode switcher (only for certificates)
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("View:").color(text_label));
                        let details_btn = egui::Button::new(
                            RichText::new("Document Details").size(theme::FONT_BODY),
                        )
                        .corner_radius(CornerRadius::same(4))
                        .fill(if self.view_mode == ViewMode::Details {
                            accent
                        } else {
                            egui::Color32::TRANSPARENT
                        });
                        if ui.add(details_btn).clicked() {
                            self.view_mode = ViewMode::Details;
                        }

                        // Show Chain View button when the selected document is a certificate
                        // and there is at least one certificate loaded
                        let chain_enabled =
                            has_any_cert && selected_doc.map(|d| !d.is_csr()).unwrap_or(false);

                        if chain_enabled {
                            let chain_btn = egui::Button::new(
                                RichText::new("Chain View").size(theme::FONT_BODY),
                            )
                            .corner_radius(CornerRadius::same(4))
                            .fill(
                                if self.view_mode == ViewMode::Chain {
                                    accent
                                } else {
                                    egui::Color32::TRANSPARENT
                                },
                            );

                            if ui.add(chain_btn).clicked() {
                                self.view_mode = ViewMode::Chain;
                            }
                        }
                    });
                    ui.add_space(8.0);

                    match self.view_mode {
                        ViewMode::Details => {
                            if let Some(doc) = selected_doc {
                                // Search box
                                let search_text =
                                    egui::TextEdit::singleline(&mut self.search_filter)
                                        .hint_text("Search fields...")
                                        .desired_width(f32::INFINITY);
                                ui.add(search_text);
                                ui.add_space(4.0);

                                let mut to_copy: Option<String> = None;
                                crate::ui::details_view::draw_document(
                                    ui,
                                    doc,
                                    &mut |text| {
                                        to_copy = Some(text);
                                    },
                                    theme_mode,
                                    &self.search_filter,
                                );

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
                                                .color(text_secondary),
                                        );
                                        ui.spinner();
                                    });
                                }

                                crate::ui::chain_view::draw_chain(ui, &chain, theme_mode);
                            }
                            #[cfg(not(feature = "network"))]
                            {
                                let certs = self.get_certs();
                                let chain = CertChain::build(certs);
                                crate::ui::chain_view::draw_chain(ui, &chain, theme_mode);
                            }
                        }
                    }
                }
            });
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::ValidityStatus;
    use std::collections::HashMap;

    fn test_app() -> CertViewerApp {
        CertViewerApp {
            documents: Vec::new(),
            doc_index: HashMap::new(),
            selected_tab: 0,
            view_mode: ViewMode::Details,
            error_msgs: Vec::new(),
            info_msg: None,
            theme_applied: false,
            theme_mode: ThemeMode::default(),
            clipboard: None,
            recent_files: Vec::new(),
            #[cfg(feature = "network")]
            completed_chain: None,
            #[cfg(feature = "network")]
            chain_completion_rx: None,
            #[cfg(feature = "network")]
            chain_completion_pending: false,
            #[cfg(feature = "network")]
            initial_chain: None,
            loading_in_progress: false,
            file_load_rx: None,
            search_filter: String::new(),
            config: crate::config::Config::default(),
        }
    }

    #[test]
    fn test_app_initial_state() {
        let app = test_app();
        assert!(app.documents.is_empty());
        assert_eq!(app.selected_tab, 0);
        assert!(app.error_msgs.is_empty());
        assert!(app.recent_files.is_empty());
    }

    #[test]
    fn test_load_valid_certificate() {
        let mut app = test_app();
        let pem = include_bytes!("../../assets/baidu.com.pem");
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
        let pem = include_bytes!("../../assets/baidu.com.pem");
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
        let csr = include_bytes!("../../assets/test.csr");
        app.load_certificate_bytes(csr);
        assert_eq!(app.documents.len(), 1);
        assert!(app.error_msgs.is_empty());
        assert!(app.documents[0].is_csr());
    }

    #[test]
    fn test_load_csr_with_extensions() {
        let mut app = test_app();
        let csr = include_bytes!("../../assets/test_with_exts.csr");
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
        let pem = include_bytes!("../../assets/baidu.com.pem");
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

    #[test]
    fn test_theme_toggle() {
        let mut app = test_app();
        assert_eq!(app.theme_mode, ThemeMode::Dark);
        app.toggle_theme();
        assert_eq!(app.theme_mode, ThemeMode::Light);
        app.toggle_theme();
        assert_eq!(app.theme_mode, ThemeMode::Dark);
    }

    #[test]
    fn test_add_to_recent() {
        let mut app = test_app();
        app.add_to_recent("/path/to/cert1.pem");
        assert_eq!(app.recent_files, vec!["/path/to/cert1.pem"]);

        app.add_to_recent("/path/to/cert2.pem");
        assert_eq!(
            app.recent_files,
            vec!["/path/to/cert2.pem", "/path/to/cert1.pem"]
        );

        // Adding same path moves it to front
        app.add_to_recent("/path/to/cert1.pem");
        assert_eq!(
            app.recent_files,
            vec!["/path/to/cert1.pem", "/path/to/cert2.pem"]
        );
    }
}
