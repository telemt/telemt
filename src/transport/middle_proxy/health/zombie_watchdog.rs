use super::*;

/// Last-resort safety net for draining writers stuck past their deadline.
///
/// Runs periodically and force-closes draining writers that remain past their deadline.
/// The watchdog keeps independent lock and removal timeouts so a stalled writer cannot
/// prevent subsequent writers from being inspected.
pub async fn me_zombie_writer_watchdog(pool: Arc<MePool>) {
    use std::time::{SystemTime, UNIX_EPOCH};

    const TICK_SECS: u64 = 30;
    const SOFT_THRESHOLD_SECS: u64 = 60;
    const HARD_THRESHOLD_SECS: u64 = 300;
    const LOCK_TIMEOUT_SECS: u64 = 5;
    const REMOVE_TIMEOUT_SECS: u64 = 10;
    const HARD_DETACH_TIMEOUT_STREAK: u8 = 3;

    let mut removal_timeout_streak = HashMap::<u64, u8>::new();

    loop {
        tokio::time::sleep(Duration::from_secs(TICK_SECS)).await;

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d.as_secs(),
            Err(_) => continue,
        };

        // Phase 1: collect zombie IDs under a short read-lock with timeout.
        let zombie_ids_with_meta: Vec<(u64, bool)> = {
            let Ok(ws) =
                tokio::time::timeout(Duration::from_secs(LOCK_TIMEOUT_SECS), pool.writers.read())
                    .await
            else {
                warn!("zombie_watchdog: writers read-lock timeout, skipping tick");
                continue;
            };
            ws.iter()
                .filter(|w| w.draining.load(std::sync::atomic::Ordering::Relaxed))
                .filter_map(|w| {
                    let deadline = w
                        .drain_deadline_epoch_secs
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if deadline == 0 {
                        return None;
                    }
                    let overdue = now.saturating_sub(deadline);
                    if overdue == 0 {
                        return None;
                    }
                    let started = w
                        .draining_started_at_epoch_secs
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let drain_age = now.saturating_sub(started);
                    if drain_age > HARD_THRESHOLD_SECS {
                        return Some((w.id, true));
                    }
                    if overdue > SOFT_THRESHOLD_SECS {
                        return Some((w.id, false));
                    }
                    None
                })
                .collect()
        };
        // read lock released here

        if zombie_ids_with_meta.is_empty() {
            removal_timeout_streak.clear();
            continue;
        }

        let mut active_zombie_ids = HashSet::<u64>::with_capacity(zombie_ids_with_meta.len());
        for (writer_id, _) in &zombie_ids_with_meta {
            active_zombie_ids.insert(*writer_id);
        }
        removal_timeout_streak.retain(|writer_id, _| active_zombie_ids.contains(writer_id));

        warn!(
            zombie_count = zombie_ids_with_meta.len(),
            soft_threshold_secs = SOFT_THRESHOLD_SECS,
            hard_threshold_secs = HARD_THRESHOLD_SECS,
            "Zombie draining writers detected by watchdog, force-closing"
        );

        // Phase 2: remove each writer individually with a timeout.
        // One stuck removal cannot block the rest.
        for (writer_id, had_clients) in &zombie_ids_with_meta {
            let result = tokio::time::timeout(
                Duration::from_secs(REMOVE_TIMEOUT_SECS),
                pool.remove_writer_and_close_clients(*writer_id),
            )
            .await;
            match result {
                Ok(()) => {
                    removal_timeout_streak.remove(writer_id);
                    pool.stats.increment_pool_force_close_total();
                    info!(writer_id, had_clients, "Zombie writer removed by watchdog");
                }
                Err(_) => {
                    let streak = removal_timeout_streak
                        .entry(*writer_id)
                        .and_modify(|value| *value = value.saturating_add(1))
                        .or_insert(1);
                    warn!(
                        writer_id,
                        had_clients,
                        timeout_streak = *streak,
                        "Zombie writer removal timed out"
                    );
                    if *streak < HARD_DETACH_TIMEOUT_STREAK {
                        continue;
                    }

                    let hard_detach = tokio::time::timeout(
                        Duration::from_secs(REMOVE_TIMEOUT_SECS),
                        pool.remove_draining_writer_hard_detach(*writer_id),
                    )
                    .await;
                    match hard_detach {
                        Ok(true) => {
                            removal_timeout_streak.remove(writer_id);
                            pool.stats.increment_pool_force_close_total();
                            info!(
                                writer_id,
                                had_clients, "Zombie writer hard-detached after repeated timeouts"
                            );
                        }
                        Ok(false) => {
                            removal_timeout_streak.remove(writer_id);
                            debug!(
                                writer_id,
                                had_clients,
                                "Zombie hard-detach skipped (writer already gone or no longer draining)"
                            );
                        }
                        Err(_) => {
                            warn!(
                                writer_id,
                                had_clients, "Zombie hard-detach timed out, will retry next tick"
                            );
                        }
                    }
                }
            }
        }
    }
}
