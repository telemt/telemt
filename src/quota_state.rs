use std::collections::BTreeMap;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::stats::{Stats, UserQuotaSnapshot};

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

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) async fn load_quota_state(path: &Path, stats: &Stats) {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            warn!(
                error = %error,
                path = %path.display(),
                "Failed to read quota state file"
            );
            return;
        }
    };

    let state = match serde_json::from_slice::<QuotaStateFile>(&bytes) {
        Ok(state) => state,
        Err(error) => {
            warn!(
                error = %error,
                path = %path.display(),
                "Failed to parse quota state file"
            );
            return;
        }
    };

    let loaded_users = state.users.len();
    for (user, quota) in state.users {
        stats.load_user_quota_state(&user, quota.used_bytes, quota.last_reset_epoch_secs);
    }
    info!(
        path = %path.display(),
        loaded_users,
        "Loaded per-user quota state"
    );
}

pub(crate) async fn save_quota_state(path: &Path, stats: &Stats) -> std::io::Result<()> {
    let mut users = BTreeMap::new();
    let mut last_reset_epoch_secs = 0;
    for (user, quota) in stats.user_quota_snapshot() {
        last_reset_epoch_secs = last_reset_epoch_secs.max(quota.last_reset_epoch_secs);
        users.insert(user, quota_user_state(quota));
    }

    let state = QuotaStateFile {
        last_reset_epoch_secs,
        users,
    };
    write_state_file(path, &state).await
}

pub(crate) async fn reset_user_quota(
    path: &Path,
    stats: &Stats,
    user: &str,
) -> std::io::Result<UserQuotaSnapshot> {
    let snapshot = stats.reset_user_quota(user);
    save_quota_state(path, stats).await?;
    Ok(snapshot)
}

async fn write_state_file(path: &Path, state: &QuotaStateFile) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }

    let tmp_path = path.with_extension(format!("tmp.{}", now_epoch_secs()));
    let payload = serde_json::to_vec_pretty(state)?;
    let mut file = tokio::fs::File::create(&tmp_path).await?;
    file.write_all(&payload).await?;
    file.write_all(b"\n").await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(&tmp_path, path).await
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

    #[test]
    fn quota_user_state_copies_fields_verbatim() {
        let snap = UserQuotaSnapshot {
            used_bytes: 123_456,
            last_reset_epoch_secs: 999,
        };
        let s = quota_user_state(snap);
        assert_eq!(s.used_bytes, 123_456);
        assert_eq!(s.last_reset_epoch_secs, 999);
    }

    #[test]
    fn quota_state_file_round_trips_through_json() {
        let mut original = QuotaStateFile {
            last_reset_epoch_secs: 1_700_000_000,
            users: BTreeMap::new(),
        };
        original.users.insert(
            "alice".to_string(),
            QuotaUserState {
                used_bytes: 42,
                last_reset_epoch_secs: 1_699_990_000,
            },
        );
        original.users.insert(
            "bob".to_string(),
            QuotaUserState {
                used_bytes: 0,
                last_reset_epoch_secs: 0,
            },
        );

        let json = serde_json::to_string(&original).unwrap();
        let back: QuotaStateFile = serde_json::from_str(&json).unwrap();

        assert_eq!(back.last_reset_epoch_secs, 1_700_000_000);
        assert_eq!(back.users.len(), 2);
        assert_eq!(back.users["alice"].used_bytes, 42);
        assert_eq!(back.users["alice"].last_reset_epoch_secs, 1_699_990_000);
        assert_eq!(back.users["bob"].used_bytes, 0);
    }

    #[test]
    fn now_epoch_secs_is_monotonic_within_a_test_run() {
        // Cheap smoke test — just ensures the helper doesn't panic and
        // returns a value > 0 on any sane system clock.
        let t1 = now_epoch_secs();
        let t2 = now_epoch_secs();
        assert!(t1 > 0, "epoch seconds must be positive");
        assert!(t2 >= t1, "time must not go backwards within a single test");
    }
}
