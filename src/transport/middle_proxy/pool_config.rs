use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use super::pool::MePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotApplyOutcome {
    AppliedChanged,
    AppliedNoDelta,
    RejectedEmpty,
}

impl SnapshotApplyOutcome {
    pub fn changed(self) -> bool {
        matches!(self, SnapshotApplyOutcome::AppliedChanged)
    }
}

impl MePool {
    pub async fn update_proxy_maps(
        &self,
        new_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        new_v6: Option<HashMap<i32, Vec<(IpAddr, u16)>>>,
    ) -> SnapshotApplyOutcome {
        if new_v4.is_empty() && new_v6.as_ref().is_none_or(|v| v.is_empty()) {
            return SnapshotApplyOutcome::RejectedEmpty;
        }

        let mut changed = false;
        {
            let mut guard = self.proxy_map_v4.write().await;
            if !new_v4.is_empty() && *guard != new_v4 {
                *guard = new_v4;
                changed = true;
            }
        }
        if let Some(v6) = new_v6 {
            let mut guard = self.proxy_map_v6.write().await;
            if !v6.is_empty() && *guard != v6 {
                *guard = v6;
                changed = true;
            }
        }
        // Ensure negative DC entries mirror positives when absent (Telegram convention).
        {
            let mut guard = self.proxy_map_v4.write().await;
            let keys: Vec<i32> = guard.keys().cloned().collect();
            for k in keys.iter().cloned().filter(|k| *k > 0) {
                if !guard.contains_key(&-k)
                    && let Some(addrs) = guard.get(&k).cloned()
                {
                    guard.insert(-k, addrs);
                    changed = true;
                }
            }
        }
        {
            let mut guard = self.proxy_map_v6.write().await;
            let keys: Vec<i32> = guard.keys().cloned().collect();
            for k in keys.iter().cloned().filter(|k| *k > 0) {
                if !guard.contains_key(&-k)
                    && let Some(addrs) = guard.get(&k).cloned()
                {
                    guard.insert(-k, addrs);
                    changed = true;
                }
            }
        }
        if changed {
            self.rebuild_endpoint_dc_map().await;
            self.notify_writer_epoch();
        }
        if changed {
            SnapshotApplyOutcome::AppliedChanged
        } else {
            SnapshotApplyOutcome::AppliedNoDelta
        }
    }

    pub async fn update_secret(self: &Arc<Self>, new_secret: Vec<u8>) -> bool {
        if new_secret.len() < 32 {
            warn!(
                len = new_secret.len(),
                "proxy-secret update ignored (too short)"
            );
            return false;
        }
        let mut guard = self.proxy_secret.write().await;
        if guard.secret != new_secret {
            guard.secret = new_secret;
            guard.key_selector = if guard.secret.len() >= 4 {
                u32::from_le_bytes([
                    guard.secret[0],
                    guard.secret[1],
                    guard.secret[2],
                    guard.secret[3],
                ])
            } else {
                0
            };
            guard.epoch = guard.epoch.saturating_add(1);
            drop(guard);
            self.reconnect_all().await;
            return true;
        }
        false
    }

    pub async fn reconnect_all(self: &Arc<Self>) {
        let ws = self.writers.read().await.clone();
        for w in ws.iter() {
            if let Ok(()) = self
                .connect_one_for_dc(w.addr, w.writer_dc, self.rng.as_ref())
                .await
            {
                self.mark_writer_draining(w.id).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
