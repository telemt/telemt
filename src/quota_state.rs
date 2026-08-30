use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::stats::{QuotaStore, UserQuotaSnapshot};

const QUOTA_STATE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const QUOTA_STATE_MAX_USERS: usize = 65_536;

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct QuotaStateFile {
    pub(crate) last_reset_epoch_secs: u64,
    pub(crate) users: BTreeMap<String, QuotaUserState>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct QuotaUserState {
    pub(crate) used_bytes: u64,
    pub(crate) last_reset_epoch_secs: u64,
}

/// Serialized process owner for bounded durable quota checkpoints and resets.
pub(crate) struct QuotaStateOwner {
    path: PathBuf,
    store: Arc<QuotaStore>,
    mutation: Arc<Mutex<()>>,
}

impl QuotaStateOwner {
    /// Creates a process-owned quota persistence coordinator.
    pub(crate) fn new(path: PathBuf, store: Arc<QuotaStore>) -> Arc<Self> {
        Arc::new(Self {
            path,
            store,
            mutation: Arc::new(Mutex::new(())),
        })
    }

    /// Returns the process-owned quota checkpoint path.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// Loads only quota entries owned by currently configured users.
    pub(crate) async fn load(&self, configured_users: &BTreeSet<String>) {
        let _guard = self.mutation.lock().await;
        let state = match read_state_file(&self.path).await {
            Ok(Some(state)) => state,
            Ok(None) => return,
            Err(error) => {
                warn!(
                    error = %error,
                    path = %self.path.display(),
                    "Failed to load quota state file"
                );
                return;
            }
        };

        let persisted_users = state.users.len();
        let mut loaded_users = 0usize;
        for (user, quota) in state.users {
            if loaded_users >= QUOTA_STATE_MAX_USERS || !configured_users.contains(&user) {
                continue;
            }
            self.store
                .load(&user, quota.used_bytes, quota.last_reset_epoch_secs);
            loaded_users = loaded_users.saturating_add(1);
        }
        info!(
            path = %self.path.display(),
            loaded_users,
            skipped_users = persisted_users.saturating_sub(loaded_users),
            "Loaded bounded per-user quota state"
        );
    }

    /// Persists a checkpoint filtered to the active configured user set.
    pub(crate) async fn save(&self, configured_users: &BTreeSet<String>) -> std::io::Result<()> {
        let guard = Arc::clone(&self.mutation).lock_owned().await;
        let state = self.state_for_users(configured_users, None);
        let path = self.path.clone();
        let task = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            write_state_file_blocking(&path, &state)
        });
        wait_for_blocking_io(task).await
    }

    /// Durably commits a prospective reset before publishing it to live counters.
    pub(crate) async fn reset_user(
        &self,
        configured_users: &BTreeSet<String>,
        user: &str,
    ) -> std::io::Result<UserQuotaSnapshot> {
        let guard = Arc::clone(&self.mutation).lock_owned().await;
        let last_reset_epoch_secs = now_epoch_secs();
        let prospective = UserQuotaSnapshot {
            used_bytes: 0,
            last_reset_epoch_secs,
        };
        let state = self.state_for_users(configured_users, Some((user, prospective.clone())));
        let path = self.path.clone();
        let store = Arc::clone(&self.store);
        let user = user.to_string();
        let task = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            write_state_file_blocking(&path, &state)?;
            Ok(store.reset(&user, last_reset_epoch_secs))
        });
        wait_for_blocking_io(task).await
    }

    /// Removes a deleted user's persisted and in-memory quota ownership.
    pub(crate) async fn remove_user(
        &self,
        configured_users: &BTreeSet<String>,
        user: &str,
    ) -> std::io::Result<()> {
        let guard = Arc::clone(&self.mutation).lock_owned().await;
        let state = self.state_for_users(configured_users, None);
        let path = self.path.clone();
        let store = Arc::clone(&self.store);
        let user = user.to_string();
        let task = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let persisted = write_state_file_blocking(&path, &state);
            store.remove(&user);
            persisted
        });
        wait_for_blocking_io(task).await
    }

    fn state_for_users(
        &self,
        configured_users: &BTreeSet<String>,
        override_user: Option<(&str, UserQuotaSnapshot)>,
    ) -> QuotaStateFile {
        let snapshot = self.store.snapshot();
        let mut users = BTreeMap::new();
        let mut last_reset_epoch_secs = 0;
        for user in configured_users.iter().take(QUOTA_STATE_MAX_USERS) {
            let quota = override_user
                .as_ref()
                .filter(|(override_name, _)| *override_name == user.as_str())
                .map(|(_, quota)| quota.clone())
                .or_else(|| snapshot.get(user).cloned());
            let Some(quota) = quota else {
                continue;
            };
            last_reset_epoch_secs = last_reset_epoch_secs.max(quota.last_reset_epoch_secs);
            users.insert(user.clone(), quota_user_state(quota));
        }
        QuotaStateFile {
            last_reset_epoch_secs,
            users,
        }
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn read_state_file(path: &Path) -> std::io::Result<Option<QuotaStateFile>> {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if file.metadata().await?.len() > QUOTA_STATE_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quota state file exceeds the 16 MiB limit",
        ));
    }
    let mut payload = Vec::new();
    file.take(QUOTA_STATE_MAX_BYTES.saturating_add(1))
        .read_to_end(&mut payload)
        .await?;
    if payload.len() as u64 > QUOTA_STATE_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quota state file grew beyond the 16 MiB limit while reading",
        ));
    }
    let state = serde_json::from_slice(&payload).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse quota state: {error}"),
        )
    })?;
    Ok(Some(state))
}

async fn write_state_file(path: &Path, state: QuotaStateFile) -> std::io::Result<()> {
    let path = path.to_path_buf();
    let task = tokio::task::spawn_blocking(move || write_state_file_blocking(&path, &state));
    wait_for_blocking_io(task).await
}

async fn wait_for_blocking_io<T>(
    task: tokio::task::JoinHandle<std::io::Result<T>>,
) -> std::io::Result<T> {
    task.await
        .map_err(|error| std::io::Error::other(format!("quota checkpoint join failed: {error}")))?
}

fn write_state_file_blocking(path: &Path, state: &QuotaStateFile) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut payload = serde_json::to_vec_pretty(state)?;
    payload.push(b'\n');
    if payload.len() as u64 > QUOTA_STATE_MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quota state payload exceeds the 16 MiB limit",
        ));
    }

    let mut last_collision = None;
    for _ in 0..8 {
        let tmp_path = path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                last_collision = Some(error);
                continue;
            }
            Err(error) => return Err(error),
        };
        let result = (|| {
            file.write_all(&payload)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&tmp_path, path)?;
            #[cfg(unix)]
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        return result;
    }
    Err(last_collision.unwrap_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "failed to allocate a unique quota checkpoint temporary file",
        )
    }))
}

fn quota_user_state(quota: UserQuotaSnapshot) -> QuotaUserState {
    QuotaUserState {
        used_bytes: quota.used_bytes,
        last_reset_epoch_secs: quota.last_reset_epoch_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_string()).collect()
    }

    #[tokio::test]
    async fn failed_durable_reset_does_not_publish_live_reset() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(QuotaStore::default());
        store.user("alice").charge(512);
        let owner = QuotaStateOwner::new(directory.path().to_path_buf(), store.clone());

        assert!(owner.reset_user(&users(&["alice"]), "alice").await.is_err());
        assert_eq!(store.used("alice"), 512);
    }

    #[tokio::test]
    async fn concurrent_resets_serialize_without_losing_committed_users() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("quota.json");
        let store = Arc::new(QuotaStore::default());
        store.user("alice").charge(512);
        store.user("bob").charge(1024);
        let owner = QuotaStateOwner::new(path.clone(), store.clone());
        let configured = Arc::new(users(&["alice", "bob"]));

        let alice_owner = owner.clone();
        let alice_users = configured.clone();
        let alice =
            tokio::spawn(async move { alice_owner.reset_user(&alice_users, "alice").await });
        let bob_owner = owner.clone();
        let bob_users = configured.clone();
        let bob = tokio::spawn(async move { bob_owner.reset_user(&bob_users, "bob").await });
        alice.await.unwrap().unwrap();
        bob.await.unwrap().unwrap();

        let state = read_state_file(&path).await.unwrap().unwrap();
        assert_eq!(state.users["alice"].used_bytes, 0);
        assert_eq!(state.users["bob"].used_bytes, 0);
        assert_eq!(store.used("alice"), 0);
        assert_eq!(store.used("bob"), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiter_does_not_release_blocking_mutation_ownership() {
        let mutation = Arc::new(Mutex::new(()));
        let guard = Arc::clone(&mutation).lock_owned().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let operation = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let _ = started_tx.send(());
            release_rx.recv().unwrap();
            Ok::<_, std::io::Error>(())
        });
        let waiter = tokio::spawn(wait_for_blocking_io(operation));
        started_rx.await.unwrap();

        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(mutation.try_lock().is_err());

        release_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                if mutation.try_lock().is_ok() {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn load_rejects_oversized_state_before_parsing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("quota.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(QUOTA_STATE_MAX_BYTES + 1).unwrap();
        let store = Arc::new(QuotaStore::default());
        let owner = QuotaStateOwner::new(path, store.clone());

        owner.load(&users(&["alice"])).await;

        assert_eq!(store.used("alice"), 0);
    }

    #[tokio::test]
    async fn load_filters_entries_without_configured_ownership() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("quota.json");
        let state = QuotaStateFile {
            last_reset_epoch_secs: 1,
            users: BTreeMap::from([
                (
                    "alice".to_string(),
                    QuotaUserState {
                        used_bytes: 512,
                        last_reset_epoch_secs: 1,
                    },
                ),
                (
                    "orphan".to_string(),
                    QuotaUserState {
                        used_bytes: 1024,
                        last_reset_epoch_secs: 1,
                    },
                ),
            ]),
        };
        write_state_file(&path, state).await.unwrap();
        let store = Arc::new(QuotaStore::default());
        let owner = QuotaStateOwner::new(path, store.clone());

        owner.load(&users(&["alice"])).await;

        assert_eq!(store.used("alice"), 512);
        assert_eq!(store.used("orphan"), 0);
        assert!(!store.snapshot().contains_key("orphan"));
    }
}
