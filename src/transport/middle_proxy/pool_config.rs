use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use super::pool::MePool;

impl MePool {
    pub async fn update_proxy_maps(
        &self,
        new_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        new_v6: Option<HashMap<i32, Vec<(IpAddr, u16)>>>,
    ) -> bool {
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
                }
            }
        }
        changed
    }

    pub async fn update_secret(self: &Arc<Self>, new_secret: Vec<u8>) -> bool {
        if new_secret.len() < 32 {
            warn!(len = new_secret.len(), "proxy-secret update ignored (too short)");
            return false;
        }
        let mut guard = self.proxy_secret.write().await;
        if *guard != new_secret {
            *guard = new_secret;
            drop(guard);
            self.reconnect_all().await;
            return true;
        }
        false
    }

    pub async fn reconnect_all(self: &Arc<Self>) {
        let ws = self.writers.read().await.clone();
        for w in ws {
            if let Ok(()) = self.connect_one(w.addr, self.rng.as_ref()).await {
                self.mark_writer_draining(w.id).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
