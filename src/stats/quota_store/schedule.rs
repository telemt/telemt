use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

use serde::{Deserialize, Serialize};

use super::{QuotaStore, UserQuotaHandle};
use crate::config::{ProxyConfig, UserQuotaPeriod};
use crate::proxy::user_admission::UserCredentialId;

/// Durable calendar watermark, independent from the last manual reset timestamp.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct QuotaScheduleCheckpoint {
    /// Effective calendar; absent leaves the existing manual-only quota policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) quota_period: Option<UserQuotaPeriod>,
    /// Monotonic processed time; activation and manual reset need not be midnight.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) period_cursor_epoch_secs: u64,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Latest API intent awaiting a matching or demonstrably newer policy source.
#[derive(Clone)]
pub(super) struct FreshSchedule {
    /// Snapshot visible at creation; preparation can publish another older snapshot later.
    pub(super) source: Weak<ProxyConfig>,
    /// Monotonic commit time, independent from quota calendar wall time.
    pub(super) created_at: std::time::Instant,
    /// Latest committed credential while a policy source is pending.
    pub(super) credential: UserCredentialId,
    /// Latest committed desired calendar.
    pub(super) period: Option<UserQuotaPeriod>,
    /// Latest committed quota amount.
    pub(super) quota: Option<u64>,
}

/// Account-owned cold state serialized by the process quota mutation gate.
#[derive(Clone, Default)]
pub(super) struct QuotaSchedule {
    /// Last successful durable calendar publication.
    pub(super) checkpoint: QuotaScheduleCheckpoint,
    /// Calendar accepted from the active runtime configuration.
    pub(super) requested: Option<UserQuotaPeriod>,
    /// Wall time captured when the requested calendar changed.
    pub(super) accepted_at: u64,
    /// Suspends the previous cadence while a policy change awaits persistence.
    pub(super) pending: bool,
    /// Reports the last unsuccessful attempt without modifying the durable cursor.
    pub(super) failed: bool,
    /// Rejects pre-mutation policies until a matching or newer source arrives.
    pub(super) fresh: Option<FreshSchedule>,
    /// Latest accepted source read or API commit; survives policy attachment.
    pub(super) policy_fence_at: Option<std::time::Instant>,
    /// Requests new read evidence after rejection without changing calendar status.
    pub(super) needs_source_refresh: bool,
}

/// Bounded replacement index: a username owns at most one deadline and dirty entry.
#[derive(Default)]
pub(super) struct ScheduleWork {
    due: BTreeSet<(u64, String)>,
    by_user: BTreeMap<String, u64>,
    dirty: BTreeSet<String>,
    removed: bool,
}

/// Consistent control-plane status; no calendar work runs on the relay path.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct QuotaScheduleStatus {
    /// Effective calendar, absent while a policy change is awaiting its checkpoint.
    pub(crate) active_quota_period: Option<UserQuotaPeriod>,
    /// UTC boundary containing the durable cursor.
    pub(crate) quota_period_start_epoch_secs: Option<u64>,
    /// First boundary strictly after the durable cursor.
    pub(crate) quota_next_reset_epoch_secs: Option<u64>,
    /// Bounded API state token; never includes internal error details.
    pub(crate) quota_schedule_state: &'static str,
}

/// A captured account and policy transition owned by the process mutation gate.
pub(crate) struct QuotaScheduleChange {
    /// Current account name used to replace one bounded work-index entry.
    pub(crate) user: String,
    /// Exact accounting incarnation captured under the process gate.
    pub(crate) target: UserQuotaHandle,
    /// Prospective metadata written before live publication.
    pub(crate) checkpoint: QuotaScheduleCheckpoint,
    /// Distinguishes a due reset from metadata-only activation.
    pub(crate) reset: bool,
}

impl QuotaStore {
    /// Shares the control-plane gate across API, scheduler, and runtime sources.
    pub(crate) fn mutation_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        Arc::clone(&self.mutation)
    }

    /// Waits for an account or policy notification; its payload is never authoritative.
    pub(crate) async fn schedule_notified(&self) {
        self.schedule_notify.notified().await;
    }

    /// Detects API fences or rejected snapshots needing new source evidence.
    pub(crate) fn has_fresh_schedules(&self) -> bool {
        self.users.iter().any(|entry| {
            entry
                .value()
                .state
                .lock()
                .current
                .as_ref()
                .is_some_and(|account| {
                    let schedule = account.counters.schedule.lock();
                    schedule.fresh.is_some() || schedule.needs_source_refresh
                })
        })
    }

    /// Returns whether reconciliation or a due boundary requires work.
    pub(crate) fn schedule_ready(&self, now: u64) -> bool {
        let work = self.schedule_work.lock();
        work.removed || !work.dirty.is_empty() || work.due.first().is_some_and(|(at, _)| *at <= now)
    }

    /// Returns the earliest deadline without scanning accounts.
    pub(crate) fn schedule_deadline(&self) -> Option<u64> {
        self.schedule_work.lock().due.first().map(|(at, _)| *at)
    }

    fn schedule_index(&self, user: &str, target: Option<&UserQuotaHandle>) {
        let schedule = target.map(|handle| handle.counters.schedule.lock().clone());
        let mut work = self.schedule_work.lock();
        if let Some(old) = work.by_user.remove(user) {
            work.due.remove(&(old, user.to_owned()));
        }
        work.dirty.remove(user);
        if let Some(state) = schedule {
            if state.pending {
                work.dirty.insert(user.to_owned());
            } else if let Some(period) = state.checkpoint.quota_period {
                match period.next(state.checkpoint.period_cursor_epoch_secs) {
                    Ok(at) => {
                        work.by_user.insert(user.to_owned(), at);
                        work.due.insert((at, user.to_owned()));
                    }
                    Err(_) => {
                        work.dirty.insert(user.to_owned());
                    }
                }
            }
        }
        drop(work);
        self.schedule_notify.notify_one();
    }

    /// Discards retired work; the next checkpoint removes its durable entry.
    pub(super) fn schedule_retired(&self, user: &str, retained_metadata: bool) {
        let had_schedule = {
            let work = self.schedule_work.lock();
            work.by_user.contains_key(user) || work.dirty.contains(user)
        };
        if had_schedule || retained_metadata {
            self.schedule_work.lock().removed = true;
        }
        self.schedule_index(user, None);
    }

    /// Attaches legacy/startup metadata without changing the loaded byte counter.
    pub(crate) fn load_schedule(&self, user: &str, checkpoint: QuotaScheduleCheckpoint) {
        let target = self.current_or_legacy_handle(user);
        *target.counters.schedule.lock() = QuotaSchedule {
            checkpoint,
            requested: checkpoint.quota_period,
            ..QuotaSchedule::default()
        };
    }

    /// Records the snapshot fence for a newly created API account.
    pub(crate) fn fence_fresh_schedule(
        &self,
        user: &str,
        source: &Arc<ProxyConfig>,
        credential: UserCredentialId,
        period: Option<UserQuotaPeriod>,
        quota: Option<u64>,
    ) {
        let target = self.current_or_legacy_handle(user);
        target.counters.schedule.lock().fresh = Some(FreshSchedule {
            source: Arc::downgrade(source),
            created_at: std::time::Instant::now(),
            credential,
            period,
            quota,
        });
    }

    /// Fences committed API intent for both existing and newly created accounts.
    pub(crate) fn refresh_fresh_schedule(&self, user: &str, config: &ProxyConfig) {
        let Some(target) = self.current_handle(user) else {
            return;
        };
        let mut schedule = target.counters.schedule.lock();
        if let Some(credential) = config
            .access
            .users
            .get(user)
            .and_then(|secret| crate::proxy::user_admission::credential_id_from_hex(secret))
        {
            let created_at = std::time::Instant::now();
            let period = config.access.user_quota_periods.get(user).copied();
            schedule.policy_fence_at = schedule.policy_fence_at.max(Some(created_at));
            // An unchanged policy needs a barrier, but no new attachment or file event.
            if schedule.fresh.is_none() && schedule.requested == period {
                return;
            }
            schedule.fresh = Some(FreshSchedule {
                source: schedule
                    .fresh
                    .as_ref()
                    .map(|fresh| fresh.source.clone())
                    .unwrap_or_default(),
                created_at,
                credential,
                period,
                quota: config.access.user_data_quota.get(user).copied(),
            });
        }
    }

    /// Accepts policy only from a current credential and an eligible config snapshot.
    pub(crate) fn request_schedule(
        &self,
        user: &str,
        incarnation: u64,
        credential: UserCredentialId,
        config: &Arc<ProxyConfig>,
        now: u64,
        accepted_after_mutation: bool,
    ) {
        let Some(target) = self.handle_exact(user, incarnation) else {
            return;
        };
        let period = config.access.user_quota_periods.get(user).copied();
        let mut schedule = target.counters.schedule.lock();
        if let Some(fresh) = &schedule.fresh {
            let same_source = fresh.source.ptr_eq(&Arc::downgrade(config));
            let read_after_creation = config
                .quota_source_read_at
                .is_some_and(|at| at > fresh.created_at);
            if (same_source || !accepted_after_mutation || !read_after_creation)
                && (credential != fresh.credential
                    || period != fresh.period
                    || config.access.user_data_quota.get(user).copied() != fresh.quota)
            {
                return;
            }
            // A matching API intent may arrive with an old admission epoch. Accept it
            // without discarding the commit barrier that protects later publications.
            schedule.policy_fence_at = schedule.policy_fence_at.max(Some(fresh.created_at));
            schedule.fresh = None;
        } else if schedule.policy_fence_at.is_some_and(|fence| {
            config
                .quota_source_read_at
                .is_none_or(|read_at| read_at < fence)
        }) {
            // The active runtime may already contain the latest disk bytes. Ask the
            // watcher for new evidence even when those bytes are otherwise unchanged.
            schedule.needs_source_refresh = true;
            return;
        }
        schedule.policy_fence_at = schedule.policy_fence_at.max(config.quota_source_read_at);
        schedule.needs_source_refresh = false;
        if schedule.requested != period {
            schedule.requested = period;
            schedule.accepted_at = now;
            schedule.pending = period != schedule.checkpoint.quota_period;
            schedule.failed = false;
        }
        drop(schedule);
        self.schedule_index(user, Some(&target));
    }

    /// Captures only dirty or due accounts after the caller owns the mutation gate.
    pub(crate) fn schedule_changes(&self, now: u64) -> std::io::Result<Vec<QuotaScheduleChange>> {
        let names = {
            let work = self.schedule_work.lock();
            work.dirty
                .iter()
                .cloned()
                .chain(
                    work.due
                        .iter()
                        .take_while(|(at, _)| *at <= now)
                        .map(|(_, user)| user.clone()),
                )
                .collect::<BTreeSet<_>>()
        };
        let mut changes = Vec::with_capacity(names.len());
        for user in names {
            let Some(target) = self.current_handle(&user) else {
                continue;
            };
            let state = target.counters.schedule.lock().clone();
            let mut checkpoint = state.checkpoint;
            let reset = if state.pending {
                checkpoint.quota_period = state.requested;
                checkpoint.period_cursor_epoch_secs =
                    checkpoint.period_cursor_epoch_secs.max(state.accepted_at);
                if let Some(period) = checkpoint.quota_period {
                    period
                        .next(checkpoint.period_cursor_epoch_secs)
                        .inspect_err(|_| {
                            target.counters.schedule.lock().failed = true;
                        })?;
                }
                false
            } else if let Some(period) = checkpoint.quota_period {
                let start = period.start(now).inspect_err(|_| {
                    target.counters.schedule.lock().failed = true;
                })?;
                if start <= checkpoint.period_cursor_epoch_secs {
                    continue;
                }
                checkpoint.period_cursor_epoch_secs = start;
                period.next(start).inspect_err(|_| {
                    target.counters.schedule.lock().failed = true;
                })?;
                true
            } else {
                continue;
            };
            changes.push(QuotaScheduleChange {
                user,
                target,
                checkpoint,
                reset,
            });
        }
        Ok(changes)
    }

    /// Publishes durable metadata without overwriting traffic accumulated during I/O.
    pub(crate) fn publish_schedule(&self, change: &QuotaScheduleChange, now: u64) {
        if change.reset {
            change.target.reset(now);
        }
        let mut schedule = change.target.counters.schedule.lock();
        schedule.checkpoint = change.checkpoint;
        schedule.pending = false;
        schedule.failed = false;
        drop(schedule);
        self.schedule_index(&change.user, Some(&change.target));
    }

    /// Marks the attempted batch without changing its accounting or cursor.
    pub(crate) fn schedule_failed(&self, changes: &[QuotaScheduleChange]) {
        for change in changes {
            change.target.counters.schedule.lock().failed = true;
        }
    }

    /// Reindexes a manual reset after its durable cursor publication.
    pub(crate) fn refresh_schedule(&self, user: &str) {
        self.schedule_index(user, self.current_handle(user).as_ref());
    }

    /// A successful full checkpoint has reconciled retired accounts as well.
    pub(crate) fn schedule_saved(&self) {
        self.schedule_work.lock().removed = false;
    }

    /// Lists current ownership, excluding deletion tombstones and stale generations.
    pub(crate) fn configured_quota_users(&self) -> BTreeSet<String> {
        self.users
            .iter()
            .filter_map(|entry| {
                entry
                    .value()
                    .state
                    .lock()
                    .current
                    .as_ref()
                    .map(|_| entry.key().clone())
            })
            .collect()
    }

    /// Resolves current ownership without creating a legacy account for a tombstone.
    pub(crate) fn current_handle(&self, user: &str) -> Option<UserQuotaHandle> {
        let slot = self.users.get(user)?;
        let state = slot.state.lock();
        let account = state.current.as_ref()?;
        Some(UserQuotaHandle {
            incarnation: account.incarnation,
            counters: Arc::clone(&account.counters),
        })
    }

    /// Reads status while the caller owns the process mutation gate.
    pub(crate) fn schedule_status(
        &self,
        user: &str,
        desired: Option<UserQuotaPeriod>,
        now: u64,
    ) -> QuotaScheduleStatus {
        let Some(target) = self.current_handle(user) else {
            return QuotaScheduleStatus {
                quota_schedule_state: if desired.is_some() {
                    "pending"
                } else {
                    "disabled"
                },
                ..Default::default()
            };
        };
        let schedule = target.counters.schedule.lock();
        let period = (!schedule.pending)
            .then_some(schedule.checkpoint.quota_period)
            .flatten();
        let cursor = schedule.checkpoint.period_cursor_epoch_secs;
        let start = period.and_then(|p| p.start(cursor).ok());
        let next = period.and_then(|p| p.next(cursor).ok());
        let state = if schedule.failed {
            "error"
        } else if schedule.pending || schedule.requested != desired || schedule.fresh.is_some() {
            "pending"
        } else if next.is_some_and(|at| at <= now) {
            "overdue"
        } else if period.is_some() {
            "active"
        } else {
            "disabled"
        };
        QuotaScheduleStatus {
            active_quota_period: period,
            quota_period_start_epoch_secs: start,
            quota_next_reset_epoch_secs: next,
            quota_schedule_state: state,
        }
    }
}

impl UserQuotaHandle {
    /// Captures the current accounting generation for a cold checkpoint.
    pub(crate) fn snapshot(&self) -> super::UserQuotaSnapshot {
        self.counters.snapshot()
    }

    /// Captures only cold calendar state; reserve/charge never take this lock.
    pub(crate) fn schedule_checkpoint(&self) -> QuotaScheduleCheckpoint {
        self.counters.schedule.lock().checkpoint
    }

    /// Keeps manual-only legacy checkpoints unchanged until a calendar is configured.
    pub(crate) fn manual_schedule_checkpoint(&self, now: u64) -> QuotaScheduleCheckpoint {
        let schedule = self.counters.schedule.lock();
        let mut checkpoint = schedule.checkpoint;
        if schedule.requested.is_some() || checkpoint != QuotaScheduleCheckpoint::default() {
            checkpoint.period_cursor_epoch_secs = checkpoint.period_cursor_epoch_secs.max(now);
        }
        checkpoint
    }

    /// Publishes a durable manual watermark without shifting the UTC cadence.
    pub(crate) fn publish_manual_schedule(&self, checkpoint: QuotaScheduleCheckpoint) {
        let mut schedule = self.counters.schedule.lock();
        schedule.checkpoint = checkpoint;
        if !schedule.pending {
            schedule.failed = false;
        }
    }
}
