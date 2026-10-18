use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicU8;

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::crypto::sha256;
use crate::stats::QuotaStore;

const REGISTRATION_PENDING: u8 = 0;
const REGISTRATION_ACTIVE: u8 = 1;
const REGISTRATION_DROPPED: u8 = 2;

// Authenticated-owner publication and RAII deregistration.
mod registration;
pub(crate) use registration::{UserAdmissionPublication, UserSessionRegistration};

/// Stable secret identity used to fence authentication across runtime generations.
pub(crate) type UserCredentialId = [u8; 16];

/// Monotonic identity of one configured username lifetime.
pub(crate) type UserIncarnation = u64;

#[derive(Clone, Copy, PartialEq, Eq)]
struct EffectiveUser {
    credential_id: UserCredentialId,
    enabled: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UserOverride {
    Present(EffectiveUser),
    Deleted,
}

struct UserRecord {
    configured: Option<EffectiveUser>,
    mutation_override: Option<UserOverride>,
    incarnation: UserIncarnation,
}

impl UserRecord {
    fn effective(&self) -> Option<EffectiveUser> {
        match self.mutation_override {
            Some(UserOverride::Present(user)) => Some(user),
            Some(UserOverride::Deleted) => None,
            None => self.configured,
        }
    }
}

struct RegisteredOwner {
    token: CancellationToken,
    incarnation: UserIncarnation,
}

#[derive(Default)]
struct UserAdmissionState {
    initialized: bool,
    epoch: u64,
    active_config_source: Option<u64>,
    stale_config_source_rejections: u64,
    next_incarnation: UserIncarnation,
    next_registration_id: u64,
    users: HashMap<String, UserRecord>,
    owners_by_user: HashMap<String, HashMap<u64, RegisteredOwner>>,
}

impl UserAdmissionState {
    fn allocate_incarnation(&mut self) -> UserIncarnation {
        self.next_incarnation = self.next_incarnation.checked_add(1).unwrap_or(u64::MAX);
        self.next_incarnation
    }

    fn allocate_registration_id(&mut self) -> Option<u64> {
        let next = self.next_registration_id.checked_add(1)?;
        self.next_registration_id = next;
        Some(next)
    }

    fn bump_epoch(&mut self) {
        self.epoch = self.epoch.checked_add(1).unwrap_or(u64::MAX);
    }

    fn owner_tokens(&self, user: &str) -> Vec<CancellationToken> {
        self.owners_by_user
            .get(user)
            .map(|owners| owners.values().map(|owner| owner.token.clone()).collect())
            .unwrap_or_default()
    }
}

/// Result of one durable user mutation applied to the process admission authority.
pub(crate) struct UserMutationResult {
    /// Incarnation invalidated or created by the mutation.
    pub(crate) incarnation: UserIncarnation,
    /// Number of live owners cancelled by the mutation.
    pub(crate) cancelled: usize,
    /// Whether the effective enabled state changed from enabled to disabled.
    pub(crate) newly_disabled: bool,
}

/// Process-owned user authentication and live-owner authority.
pub(crate) struct UserAdmissionAuthority {
    state: Mutex<UserAdmissionState>,
    quota_store: Arc<QuotaStore>,
}

impl UserAdmissionAuthority {
    /// Creates an uninitialized authority for isolated tests and startup wiring.
    pub(crate) fn new() -> Arc<Self> {
        Self::new_with_quota_store(Arc::new(QuotaStore::default()))
    }

    /// Creates an authority coupled to the process-scoped quota identity store.
    pub(crate) fn new_with_quota_store(quota_store: Arc<QuotaStore>) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(UserAdmissionState::default()),
            quota_store,
        })
    }

    /// Requests source-evidence refresh only while a fresh account is fenced.
    pub(crate) fn has_fresh_quota_schedules(&self) -> bool {
        self.quota_store.has_fresh_schedules()
    }

    /// Shares the process quota gate with lifecycle publication callers.
    pub(crate) fn quota_mutation_gate(&self) -> Arc<tokio::sync::Mutex<()>> {
        self.quota_store.mutation_gate()
    }

    /// Publishes calendars only for credentials owned by the active config source.
    /// The caller holds the process quota gate; disabled users retain their calendar.
    pub(crate) fn publish_quota_config(
        &self,
        source: u64,
        config: &Arc<crate::config::ProxyConfig>,
        accepted_after_mutation: bool,
    ) {
        let state = self.state.lock();
        if state.active_config_source != Some(source) {
            return;
        }
        let now = crate::quota_state::now_epoch_secs();
        for (user, secret) in &config.access.users {
            let Some(credential) = credential_id_from_hex(secret) else {
                continue;
            };
            let Some(record) = state.users.get(user) else {
                continue;
            };
            if record
                .effective()
                .is_some_and(|effective| effective.credential_id == credential)
            {
                self.quota_store.request_schedule(
                    user,
                    record.incarnation,
                    credential,
                    config,
                    now,
                    accepted_after_mutation,
                );
            }
        }
    }

    /// Returns the mutation epoch used to reject stale candidate configuration.
    pub(crate) fn epoch(&self) -> u64 {
        self.state.lock().epoch
    }

    /// Reconciles the complete configured user set into the process authority.
    pub(crate) fn apply_config(
        &self,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Vec<(String, usize)> {
        self.activate_config_source(0, None, users, user_enabled)
            .unwrap_or_default()
    }

    /// Transfers configuration ownership to one runtime generation.
    pub(crate) fn activate_config_source(
        &self,
        source_generation: u64,
        expected_epoch: Option<u64>,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Option<Vec<(String, usize)>> {
        self.apply_config_locked(source_generation, expected_epoch, true, users, user_enabled)
    }

    /// Reconciles an update only while its runtime generation owns configuration.
    pub(crate) fn apply_config_from_source(
        &self,
        source_generation: u64,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Option<Vec<(String, usize)>> {
        self.apply_config_locked(source_generation, None, false, users, user_enabled)
    }

    /// Returns the number of rejected updates from non-owning generations.
    pub(crate) fn stale_config_source_rejections(&self) -> u64 {
        self.state.lock().stale_config_source_rejections
    }

    fn apply_config_locked(
        &self,
        source_generation: u64,
        expected_epoch: Option<u64>,
        activate_source: bool,
        users: &HashMap<String, String>,
        user_enabled: &HashMap<String, bool>,
    ) -> Option<Vec<(String, usize)>> {
        let configured = users
            .iter()
            .filter_map(|(user, secret)| {
                credential_id_from_hex(secret).map(|credential_id| {
                    (
                        user.clone(),
                        EffectiveUser {
                            credential_id,
                            enabled: user_enabled.get(user).copied().unwrap_or(true),
                        },
                    )
                })
            })
            .collect::<HashMap<_, _>>();
        let cancellations = {
            let mut state = self.state.lock();
            if activate_source {
                if state
                    .active_config_source
                    .is_some_and(|active| source_generation < active)
                {
                    state.stale_config_source_rejections =
                        state.stale_config_source_rejections.saturating_add(1);
                    return None;
                }
                state.active_config_source = Some(source_generation);
            } else if state.active_config_source != Some(source_generation) {
                state.stale_config_source_rejections =
                    state.stale_config_source_rejections.saturating_add(1);
                return None;
            }
            if expected_epoch.is_some_and(|epoch| state.epoch != epoch) {
                return None;
            }

            let mut changed = !state.initialized;
            state.initialized = true;
            let existing_users = state.users.keys().cloned().collect::<Vec<_>>();
            let mut cancellations = Vec::new();

            for user in existing_users {
                let desired = configured.get(&user).copied();
                let old_effective = state.users.get(&user).and_then(UserRecord::effective);
                let override_matches = state.users.get(&user).is_some_and(|record| {
                    matches!(
                        (record.mutation_override, desired),
                        (Some(UserOverride::Present(current)), Some(next)) if current == next
                    ) || matches!(
                        (record.mutation_override, desired),
                        (Some(UserOverride::Deleted), None)
                    )
                });

                if let Some(record) = state.users.get_mut(&user) {
                    if record.configured != desired || override_matches {
                        changed = true;
                    }
                    record.configured = desired;
                    if override_matches {
                        record.mutation_override = None;
                    }
                }

                let new_effective = state.users.get(&user).and_then(UserRecord::effective);
                if old_effective != new_effective {
                    let identity_changed = old_effective.map(|entry| entry.credential_id)
                        != new_effective.map(|entry| entry.credential_id);
                    if identity_changed {
                        let incarnation = state.allocate_incarnation();
                        if let Some(record) = state.users.get_mut(&user) {
                            record.incarnation = incarnation;
                        }
                        match (old_effective, new_effective) {
                            (None, Some(_)) => {
                                self.quota_store.activate_fresh(&user, incarnation);
                            }
                            (Some(_), Some(_)) => {
                                self.quota_store
                                    .advance_preserving_usage(&user, incarnation);
                            }
                            (Some(_), None) => {
                                self.quota_store.retire_through(&user, incarnation);
                            }
                            (None, None) => {}
                        }
                    }
                    if identity_changed
                        || old_effective.is_some_and(|entry| entry.enabled)
                            && new_effective.is_none_or(|entry| !entry.enabled)
                    {
                        let tokens = state.owner_tokens(&user);
                        cancellations.push((user, tokens));
                    }
                }
            }

            for (user, desired) in configured {
                if state.users.contains_key(&user) {
                    continue;
                }
                changed = true;
                let incarnation = state.allocate_incarnation();
                state.users.insert(
                    user.clone(),
                    UserRecord {
                        configured: Some(desired),
                        mutation_override: None,
                        incarnation,
                    },
                );
                self.quota_store.activate_fresh(&user, incarnation);
            }

            if changed {
                state.bump_epoch();
            }
            cancellations
        };
        Some(cancel_owners(cancellations))
    }

    /// Applies one persisted user value ahead of asynchronous runtime reload.
    pub(crate) fn stage_user(
        &self,
        user: &str,
        secret: &str,
        enabled: bool,
    ) -> Option<UserMutationResult> {
        let credential_id = credential_id_from_hex(secret)?;
        Some(self.stage_user_credential(user, credential_id, enabled))
    }

    /// Applies one already validated credential mutation ahead of runtime reload.
    pub(crate) fn stage_user_credential(
        &self,
        user: &str,
        credential_id: UserCredentialId,
        enabled: bool,
    ) -> UserMutationResult {
        let desired = EffectiveUser {
            credential_id,
            enabled,
        };
        let (incarnation, newly_disabled, tokens) = {
            let mut state = self.state.lock();
            let previous = state.users.get(user).and_then(UserRecord::effective);
            let identity_changed = previous.map(|entry| entry.credential_id) != Some(credential_id);
            let incarnation = if identity_changed {
                state.allocate_incarnation()
            } else {
                state
                    .users
                    .get(user)
                    .map(|record| record.incarnation)
                    .unwrap_or_else(|| state.allocate_incarnation())
            };
            let record = state.users.entry(user.to_string()).or_insert(UserRecord {
                configured: None,
                mutation_override: None,
                incarnation,
            });
            record.mutation_override = Some(UserOverride::Present(desired));
            record.incarnation = incarnation;
            if identity_changed {
                if previous.is_some() {
                    self.quota_store.advance_preserving_usage(user, incarnation);
                } else {
                    self.quota_store.activate_fresh(user, incarnation);
                }
            }
            state.initialized = true;
            state.bump_epoch();
            let newly_disabled = previous.is_some_and(|entry| entry.enabled) && !enabled;
            let tokens = if identity_changed || !enabled {
                state.owner_tokens(user)
            } else {
                Vec::new()
            };
            (incarnation, newly_disabled, tokens)
        };
        let cancelled = tokens.len();
        for token in tokens {
            token.cancel();
        }
        UserMutationResult {
            incarnation,
            cancelled,
            newly_disabled,
        }
    }

    /// Installs a deletion tombstone and cancels every owner of the old incarnation.
    pub(crate) fn delete_user(&self, user: &str) -> UserMutationResult {
        let (incarnation, newly_disabled, tokens) = {
            let mut state = self.state.lock();
            let previous = state.users.get(user).and_then(UserRecord::effective);
            let incarnation = state.allocate_incarnation();
            let record = state.users.entry(user.to_string()).or_insert(UserRecord {
                configured: None,
                mutation_override: None,
                incarnation,
            });
            record.mutation_override = Some(UserOverride::Deleted);
            record.incarnation = incarnation;
            self.quota_store.retire_through(user, incarnation);
            state.initialized = true;
            state.bump_epoch();
            (
                incarnation,
                previous.is_some_and(|entry| entry.enabled),
                state.owner_tokens(user),
            )
        };
        let cancelled = tokens.len();
        for token in tokens {
            token.cancel();
        }
        UserMutationResult {
            incarnation,
            cancelled,
            newly_disabled,
        }
    }

    /// Returns whether the effective process policy currently enables a user.
    pub(crate) fn is_user_enabled(&self, user: &str) -> bool {
        let state = self.state.lock();
        if !state.initialized {
            return true;
        }
        state
            .users
            .get(user)
            .and_then(UserRecord::effective)
            .is_some_and(|entry| entry.enabled)
    }

    /// Returns the authenticated incarnation for an exact current credential.
    pub(crate) fn authenticated_incarnation(
        &self,
        user: &str,
        credential_id: UserCredentialId,
    ) -> Option<UserIncarnation> {
        let state = self.state.lock();
        if !state.initialized {
            return Some(0);
        }
        let record = state.users.get(user)?;
        let effective = record.effective()?;
        (effective.enabled && effective.credential_id == credential_id)
            .then_some(record.incarnation)
    }

    /// Starts a short publication critical section for one authenticated owner.
    pub(crate) fn claim_authenticated(
        self: &Arc<Self>,
        user: &str,
        credential_id: UserCredentialId,
    ) -> Option<UserAdmissionPublication<'_>> {
        let mut state = self.state.lock();
        let incarnation = if state.initialized {
            let record = state.users.get(user)?;
            let effective = record.effective()?;
            if !effective.enabled || effective.credential_id != credential_id {
                return None;
            }
            record.incarnation
        } else {
            0
        };
        let registration_id = state.allocate_registration_id()?;
        let token = CancellationToken::new();
        let active = Arc::new(AtomicU8::new(REGISTRATION_PENDING));
        Some(UserAdmissionPublication {
            state,
            authority: Arc::clone(self),
            user: user.to_string(),
            registration_id,
            incarnation,
            token,
            active,
            registration_taken: false,
        })
    }

    /// Registers a legacy owner when no credential snapshot is available.
    pub(crate) fn register_legacy(self: &Arc<Self>, user: &str) -> Option<UserSessionRegistration> {
        let credential_id = {
            let state = self.state.lock();
            if !state.initialized {
                [0; 16]
            } else {
                state.users.get(user)?.effective()?.credential_id
            }
        };
        let mut publication = self.claim_authenticated(user, credential_id)?;
        let registration = publication.take_registration()?;
        publication.commit();
        Some(registration)
    }

    /// Cancels all current owners without changing admission policy.
    pub(crate) fn cancel_user_owners(&self, user: &str) -> usize {
        let tokens = self.state.lock().owner_tokens(user);
        let count = tokens.len();
        for token in tokens {
            token.cancel();
        }
        count
    }

    fn unregister(&self, user: &str, registration_id: u64, incarnation: UserIncarnation) {
        let mut state = self.state.lock();
        let remove_user = state
            .owners_by_user
            .get_mut(user)
            .map(|owners| {
                if owners
                    .get(&registration_id)
                    .is_some_and(|owner| owner.incarnation == incarnation)
                {
                    owners.remove(&registration_id);
                }
                owners.is_empty()
            })
            .unwrap_or(false);
        if remove_user {
            state.owners_by_user.remove(user);
        }
    }
}

/// Derives the stable credential identity from one decoded MTProxy secret.
pub(crate) fn credential_id(secret: &[u8; 16]) -> UserCredentialId {
    let digest = sha256(secret);
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    id
}

/// Decodes one configured secret and derives its credential identity.
pub(crate) fn credential_id_from_hex(secret: &str) -> Option<UserCredentialId> {
    let decoded = hex::decode(secret).ok()?;
    let secret: [u8; 16] = decoded.try_into().ok()?;
    Some(credential_id(&secret))
}

fn cancel_owners(cancellations: Vec<(String, Vec<CancellationToken>)>) -> Vec<(String, usize)> {
    cancellations
        .into_iter()
        .map(|(user, tokens)| {
            let count = tokens.len();
            for token in tokens {
                token.cancel();
            }
            (user, count)
        })
        .collect()
}

#[cfg(test)]
#[path = "user_admission/tests.rs"]
mod tests;
