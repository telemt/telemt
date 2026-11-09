//! Bounded source evidence and owner-authored configuration observations.
//! These records describe publication, never asynchronous consumer convergence.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use serde::Serialize;
use sha2::{Digest, Sha256};

pub(crate) fn source_revision(sources: &BTreeMap<PathBuf, String>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"telemt-config-manifest-v1\0");
    for (path, content) in sources {
        let path = path.as_os_str().as_encoded_bytes();
        hash.update((path.len() as u64).to_le_bytes());
        hash.update(path);
        hash.update((content.len() as u64).to_le_bytes());
        hash.update(content.as_bytes());
    }
    hex::encode(hash.finalize())
}

#[derive(Debug, Clone, Default)]
pub(crate) enum ConfigProvenance {
    #[default]
    Unknown,
    Source(Arc<SourceEvidence>),
    /// The published config combines sources or retained process policy. Do not
    /// attribute all its values to the last source read by the watcher.
    Mixed,
}

impl ConfigProvenance {
    pub(crate) fn revision(&self) -> Option<&str> {
        match self {
            Self::Source(source) => Some(&source.revision),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct SourceEvidence {
    pub(crate) revision: String,
    pub(crate) explicit_paths: BTreeSet<String>,
    pub(crate) complete: bool,
    pub(crate) source_count: usize,
    pub(crate) generated_fake_cert_len: bool,
}

impl SourceEvidence {
    pub(crate) fn capture(
        document: &toml::Value,
        sources: &BTreeMap<PathBuf, String>,
    ) -> Arc<Self> {
        fn visit(
            value: &toml::Value,
            path: &str,
            paths: &mut BTreeSet<String>,
            complete: &mut bool,
        ) {
            if paths.len() >= 4096 || path.len() > 256 {
                *complete = false;
                return;
            }
            if !path.is_empty() {
                paths.insert(path.to_owned());
            }
            // Open maps need only presence provenance, never their private keys.
            if path == "dc_overrides"
                || path == "censorship.exclusive_mask"
                || path.starts_with("access.")
            {
                return;
            }
            match value {
                toml::Value::Table(table) => {
                    for (key, value) in table {
                        let key = if path.starts_with("upstreams[")
                            && path.ends_with(']')
                            && key == "force_bind"
                        {
                            "bindtodevice"
                        } else if path == "server" && key == "admin_api" {
                            "api"
                        } else {
                            key
                        };
                        let child = if path.is_empty() {
                            key.to_owned()
                        } else {
                            format!("{path}.{key}")
                        };
                        visit(value, &child, paths, complete);
                    }
                }
                toml::Value::Array(array) => {
                    for (index, value) in array.iter().enumerate() {
                        visit(value, &format!("{path}[{index}]"), paths, complete);
                    }
                }
                _ => {}
            }
        }
        let mut explicit_paths = BTreeSet::new();
        let mut complete = true;
        visit(document, "", &mut explicit_paths, &mut complete);
        let censorship = document.get("censorship");
        let generated_fake_cert_len = censorship
            .and_then(|v| v.get("tls_emulation"))
            .and_then(toml::Value::as_bool)
            == Some(false)
            && censorship
                .and_then(|v| v.get("fake_cert_len"))
                .and_then(toml::Value::as_integer)
                .is_none_or(|value| value == super::defaults::default_fake_cert_len() as i64);
        Arc::new(Self {
            revision: source_revision(sources),
            explicit_paths,
            complete,
            source_count: sources.len(),
            generated_fake_cert_len,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct WatchOutcome {
    pub(crate) sequence: u64,
    pub(crate) observed_at_epoch_secs: u64,
    pub(crate) phase: &'static str,
    /// Source considered by this attempt, not a hash of applied runtime state.
    pub(crate) source_revision: Option<String>,
    pub(crate) published_config_epoch: Option<u64>,
    pub(crate) error_code: Option<&'static str>,
}

#[derive(Debug, Default)]
pub(crate) struct WatchObservation {
    next_sequence: AtomicU64,
    latest: ArcSwapOption<WatchOutcome>,
}

impl WatchObservation {
    pub(crate) fn record(
        &self,
        phase: &'static str,
        revision: Option<String>,
        epoch: Option<u64>,
        error_code: Option<&'static str>,
    ) {
        self.latest.store(Some(Arc::new(WatchOutcome {
            sequence: self
                .next_sequence
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1),
            observed_at_epoch_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            phase,
            source_revision: revision,
            published_config_epoch: epoch,
            error_code,
        })));
    }

    pub(crate) fn snapshot(&self) -> Option<Arc<WatchOutcome>> {
        self.latest.load_full()
    }
}
