//! Certificate chain local cache.
//!
//! Provides on-disk caching of downloaded certificates to avoid redundant
//! network requests when building certificate chains.

use crate::cert::ParsedCert;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{info, warn};

/// A cached certificate entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedCert {
    /// SHA-256 fingerprint.
    fingerprint: String,
    /// Subject DN.
    subject: String,
    /// The raw DER bytes, base64-encoded.
    der_base64: String,
    /// Timestamp when the certificate was cached.
    cached_at: i64,
}

/// A cache index that maps subjects to cached certificates.
#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheIndex {
    /// Map from subject DN to list of cached certificates.
    by_subject: HashMap<String, Vec<CachedCert>>,
    /// Map from fingerprint to cached certificate.
    by_fingerprint: HashMap<String, CachedCert>,
}

/// Local chain cache using the system's cache directory.
pub struct ChainCache {
    cache_dir: PathBuf,
}

impl ChainCache {
    /// Create a new chain cache using the `directories` crate to locate the
    /// platform-appropriate cache directory.
    pub fn new() -> Self {
        let cache_dir = directories::ProjectDirs::from("", "", "cer-viewer")
            .map(|dirs| dirs.cache_dir().to_path_buf())
            .unwrap_or_else(|| std::env::temp_dir().join("cer-viewer-cache"));

        // Ensure the cache directory exists
        if let Err(e) = std::fs::create_dir_all(&cache_dir) {
            warn!("Failed to create cache directory {:?}: {}", cache_dir, e);
        }

        Self { cache_dir }
    }

    /// Create a chain cache with a specific directory (for testing).
    #[allow(dead_code)]
    pub(crate) fn with_dir(dir: PathBuf) -> Self {
        let _ = std::fs::create_dir_all(&dir);
        Self { cache_dir: dir }
    }

    /// Path to the index file.
    fn index_path(&self) -> PathBuf {
        self.cache_dir.join("index.json")
    }

    /// Load the cache index from disk.
    fn load_index(&self) -> CacheIndex {
        let path = self.index_path();
        if !path.exists() {
            return CacheIndex::default();
        }
        match std::fs::read_to_string(&path) {
            Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
            Err(e) => {
                warn!("Failed to read cache index: {}", e);
                CacheIndex::default()
            }
        }
    }

    /// Save the cache index to disk.
    fn save_index(&self, index: &CacheIndex) -> Result<(), String> {
        let path = self.index_path();
        let data = serde_json::to_string_pretty(index)
            .map_err(|e| format!("Failed to serialize index: {e}"))?;
        std::fs::write(&path, data).map_err(|e| format!("Failed to write cache index: {e}"))?;
        Ok(())
    }

    /// Look up cached certificates by subject DN.
    ///
    /// Returns certificates whose subject matches the given string.
    pub fn lookup_by_subject(&self, subject: &str) -> Vec<ParsedCert> {
        let index = self.load_index();
        let entries = index.by_subject.get(subject).cloned().unwrap_or_default();

        let mut certs = Vec::new();
        for entry in entries {
            if let Some(cert) = self.parse_cached_entry(&entry) {
                certs.push(cert);
            }
        }
        certs
    }

    /// Look up a single cached certificate by SHA-256 fingerprint.
    #[allow(dead_code)]
    pub fn lookup_by_fingerprint(&self, fingerprint: &str) -> Option<ParsedCert> {
        let index = self.load_index();
        let entry = index.by_fingerprint.get(fingerprint)?;
        self.parse_cached_entry(entry)
    }

    /// Save a certificate to the cache.
    pub fn save(&self, cert: &ParsedCert) -> Result<(), String> {
        let mut index = self.load_index();

        let der_base64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &cert.raw_der);
        let cached_at = chrono::Utc::now().timestamp();

        let entry = CachedCert {
            fingerprint: cert.sha256_fingerprint.clone(),
            subject: cert.subject.clone(),
            der_base64,
            cached_at,
        };

        // Add to fingerprint index
        index
            .by_fingerprint
            .insert(cert.sha256_fingerprint.clone(), entry.clone());

        // Add to subject index
        index
            .by_subject
            .entry(cert.subject.clone())
            .or_default()
            .push(entry);

        self.save_index(&index)?;
        info!(
            "Cached certificate: {} ({})",
            cert.display_name, cert.sha256_fingerprint
        );
        Ok(())
    }

    /// Remove cached entries older than `max_age_days`.
    ///
    /// Returns the number of entries removed.
    pub fn cleanup(&self, max_age_days: u64) -> Result<usize, String> {
        let index = self.load_index();
        let cutoff = chrono::Utc::now().timestamp() - (max_age_days as i64 * 86400);

        let mut removed = 0;
        let mut new_index = CacheIndex::default();

        for (fingerprint, entry) in index.by_fingerprint {
            if entry.cached_at > cutoff {
                new_index.by_fingerprint.insert(fingerprint, entry.clone());
                new_index
                    .by_subject
                    .entry(entry.subject.clone())
                    .or_default()
                    .push(entry);
            } else {
                removed += 1;
            }
        }

        if removed > 0 {
            self.save_index(&new_index)?;
            info!("Cleaned up {} expired cache entries", removed);
        }

        Ok(removed)
    }

    /// Clear all cached entries.
    pub fn clear(&self) -> Result<usize, String> {
        let index = self.load_index();
        let count = index.by_fingerprint.len();

        let path = self.index_path();
        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| format!("Failed to clear cache: {e}"))?;
        }

        // Also remove any DER files
        if let Ok(entries) = std::fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "der") {
                    let _ = std::fs::remove_file(path);
                }
            }
        }

        info!("Cleared cache ({} entries)", count);
        Ok(count)
    }

    /// Return information about the cache (entry count, directory path).
    pub fn info(&self) -> CacheInfo {
        let index = self.load_index();
        CacheInfo {
            entry_count: index.by_fingerprint.len(),
            cache_dir: self.cache_dir.clone(),
            index_size_bytes: std::fs::metadata(self.index_path())
                .map(|m| m.len() as usize)
                .unwrap_or(0),
        }
    }

    /// Parse a cached entry back into a ParsedCert.
    fn parse_cached_entry(&self, entry: &CachedCert) -> Option<ParsedCert> {
        let der = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &entry.der_base64,
        )
        .ok()?;

        crate::cert::parse_der_certificate(&der).ok()
    }
}

/// Information about the cache state.
#[derive(Debug, Clone)]
pub struct CacheInfo {
    /// Number of cached certificates.
    pub entry_count: usize,
    /// Path to the cache directory.
    pub cache_dir: PathBuf,
    /// Size of the index file in bytes.
    pub index_size_bytes: usize,
}

impl std::fmt::Display for CacheInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Cache: {} entries, {:.1} KB, dir: {}",
            self.entry_count,
            self.index_size_bytes as f64 / 1024.0,
            self.cache_dir.display()
        )
    }
}

/// Get the default chain cache instance.
///
/// This creates a lazily-initialized static cache. It is intended to be called
/// from `complete_chain()` to avoid repeated cache directory lookups.
#[allow(dead_code)]
pub fn default_cache() -> ChainCache {
    ChainCache::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_real_cert() -> ParsedCert {
        let pem = include_bytes!("../../assets/baidu.com.pem");
        crate::cert::parse_pem_certificate(pem).unwrap()
    }

    #[test]
    fn test_cache_new_creates_dir() {
        let dir = std::env::temp_dir().join("cer_viewer_cache_test_new");
        let _ = std::fs::remove_dir_all(&dir);
        let _cache = ChainCache::with_dir(dir.clone());
        assert!(dir.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_save_and_lookup_fingerprint() {
        let dir = std::env::temp_dir().join("cer_viewer_cache_test_fp");
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ChainCache::with_dir(dir.clone());

        let cert = make_real_cert();
        let fp = cert.sha256_fingerprint.clone();

        cache.save(&cert).unwrap();
        let found = cache.lookup_by_fingerprint(&fp);
        assert!(found.is_some());
        assert_eq!(found.unwrap().subject, cert.subject);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_save_and_lookup_subject() {
        let dir = std::env::temp_dir().join("cer_viewer_cache_test_subj");
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ChainCache::with_dir(dir.clone());

        let cert = make_real_cert();
        let subject = cert.subject.clone();

        cache.save(&cert).unwrap();
        let found = cache.lookup_by_subject(&subject);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].display_name, cert.display_name);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_lookup_missing() {
        let dir = std::env::temp_dir().join("cer_viewer_cache_test_miss");
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ChainCache::with_dir(dir.clone());

        let found = cache.lookup_by_fingerprint("nonexistent");
        assert!(found.is_none());

        let found = cache.lookup_by_subject("nonexistent");
        assert!(found.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_cleanup() {
        let dir = std::env::temp_dir().join("cer_viewer_cache_test_cleanup");
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ChainCache::with_dir(dir.clone());

        let cert = make_real_cert();
        cache.save(&cert).unwrap();

        // Cleanup with 0 days should remove everything
        let removed = cache.cleanup(0).unwrap();
        assert_eq!(removed, 1);

        // Verify it's gone
        let found = cache.lookup_by_fingerprint(&cert.sha256_fingerprint);
        assert!(found.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_clear() {
        let dir = std::env::temp_dir().join("cer_viewer_cache_test_clear");
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ChainCache::with_dir(dir.clone());

        let cert = make_real_cert();
        cache.save(&cert).unwrap();

        let cleared = cache.clear().unwrap();
        assert_eq!(cleared, 1);

        let info = cache.info();
        assert_eq!(info.entry_count, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_info() {
        let dir = std::env::temp_dir().join("cer_viewer_cache_test_info");
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ChainCache::with_dir(dir.clone());

        let cert = make_real_cert();
        cache.save(&cert).unwrap();

        let info = cache.info();
        assert_eq!(info.entry_count, 1);
        assert!(info.index_size_bytes > 0);

        let display = format!("{info}");
        assert!(display.contains("1 entries"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cache_empty_subject_lookup() {
        let dir = std::env::temp_dir().join("cer_viewer_cache_test_empty");
        let _ = std::fs::remove_dir_all(&dir);
        let cache = ChainCache::with_dir(dir.clone());

        let results = cache.lookup_by_subject("CN=nonexistent");
        assert!(results.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
