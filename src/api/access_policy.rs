//! Administrative access defaults and CIDR shaping; publication uses the watcher.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Serialize};

use super::ApiShared;
use super::config_edit::{RuntimeBaseline, RuntimeFence};
use super::config_store::{
    FieldEdit, compute_snapshot_revision, load_candidate_snapshot, load_config_snapshot,
    prepare_field_edits, write_atomic_with_runtime_check,
};
use super::model::ApiFailure;
use super::patch::{Patch, patch_field};
use crate::config::{
    AccessConfig, CidrRateLimitKey, ProxyConfig, RateLimitBps, UserMaxUniqueIpsMode,
};

pub(super) const FIELDS: &[&str] = &[
    "user_max_tcp_conns_global_each",
    "user_max_unique_ips_global_each",
    "user_max_unique_ips_mode",
    "user_max_unique_ips_window_secs",
    "cidr_rate_limits",
];

#[derive(Debug, Serialize, PartialEq)]
pub(super) struct Policy {
    user_max_tcp_conns_global_each: usize,
    user_max_unique_ips_global_each: usize,
    user_max_unique_ips_mode: UserMaxUniqueIpsMode,
    user_max_unique_ips_window_secs: u64,
    cidr_rate_limits: BTreeMap<String, RateLimitBps>,
}

impl From<&AccessConfig> for Policy {
    fn from(access: &AccessConfig) -> Self {
        Self {
            user_max_tcp_conns_global_each: access.user_max_tcp_conns_global_each,
            user_max_unique_ips_global_each: access.user_max_unique_ips_global_each,
            user_max_unique_ips_mode: access.user_max_unique_ips_mode,
            user_max_unique_ips_window_secs: access.user_max_unique_ips_window_secs,
            cidr_rate_limits: access
                .cidr_rate_limits
                .iter()
                .map(|(key, value)| (key.to_string(), *value))
                .collect(),
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct PolicyState {
    desired: Policy,
    effective: Policy,
    runtime: RuntimeBaseline,
    published_match: bool,
    effective_scope: &'static str,
    subsystem_convergence: &'static str,
    apply_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    changed_paths: Option<Vec<String>>,
}

fn view(
    desired: &ProxyConfig,
    fence: &RuntimeFence,
    changed_paths: Option<Vec<String>>,
) -> PolicyState {
    let desired = Policy::from(&desired.access);
    let effective = Policy::from(&fence.config.access);
    PolicyState {
        published_match: desired == effective,
        desired,
        effective,
        runtime: fence.baseline(),
        effective_scope: "active_config_snapshot",
        subsystem_convergence: "unknown",
        apply_mode: "watcher",
        changed_paths,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PolicyPatch {
    #[serde(default, deserialize_with = "patch_field")]
    user_max_tcp_conns_global_each: Patch<usize>,
    #[serde(default, deserialize_with = "patch_field")]
    user_max_unique_ips_global_each: Patch<usize>,
    #[serde(default, deserialize_with = "patch_field")]
    user_max_unique_ips_mode: Patch<UserMaxUniqueIpsMode>,
    #[serde(default, deserialize_with = "patch_field")]
    user_max_unique_ips_window_secs: Patch<u64>,
    #[serde(default, deserialize_with = "patch_field")]
    cidr_rate_limits: Patch<BTreeMap<String, Option<RateInput>>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RateInput {
    #[serde(default)]
    up_bps: u64,
    #[serde(default)]
    down_bps: u64,
}

fn scalar<T: Serialize>(
    field: &str,
    patch: Patch<T>,
    current: &mut T,
    default: T,
    edits: &mut Vec<FieldEdit>,
) -> Result<(), ApiFailure> {
    let value = match patch {
        Patch::Unchanged => return Ok(()),
        Patch::Remove => {
            *current = default;
            None
        }
        Patch::Set(value) => {
            let rendered = toml::Value::try_from(&value).map_err(|_| {
                ApiFailure::bad_request("Policy value cannot be represented in TOML")
            })?;
            *current = value;
            Some(rendered)
        }
    };
    edits.push(FieldEdit::new(&["access", field], value));
    Ok(())
}

fn parse_key(key: &str) -> Result<CidrRateLimitKey, ApiFailure> {
    serde_json::from_value(serde_json::Value::String(key.to_owned())).map_err(|_| {
        ApiFailure::bad_request("cidr_rate_limits keys must be CIDRs or *4/N, *6/N, */N templates")
    })
}

fn apply(
    loaded: &crate::config::ParsedConfigSource,
    body: PolicyPatch,
) -> Result<(ProxyConfig, Vec<FieldEdit>), ApiFailure> {
    let mut config = loaded.config.clone();
    let defaults = AccessConfig::default();
    let access = &mut config.access;
    let mut edits = Vec::new();
    scalar(
        "user_max_tcp_conns_global_each",
        body.user_max_tcp_conns_global_each,
        &mut access.user_max_tcp_conns_global_each,
        defaults.user_max_tcp_conns_global_each,
        &mut edits,
    )?;
    scalar(
        "user_max_unique_ips_global_each",
        body.user_max_unique_ips_global_each,
        &mut access.user_max_unique_ips_global_each,
        defaults.user_max_unique_ips_global_each,
        &mut edits,
    )?;
    scalar(
        "user_max_unique_ips_mode",
        body.user_max_unique_ips_mode,
        &mut access.user_max_unique_ips_mode,
        defaults.user_max_unique_ips_mode,
        &mut edits,
    )?;
    scalar(
        "user_max_unique_ips_window_secs",
        body.user_max_unique_ips_window_secs,
        &mut access.user_max_unique_ips_window_secs,
        defaults.user_max_unique_ips_window_secs,
        &mut edits,
    )?;
    match body.cidr_rate_limits {
        Patch::Unchanged => {}
        Patch::Remove => {
            access.cidr_rate_limits.clear();
            edits.push(FieldEdit::new(&["access", "cidr_rate_limits"], None));
        }
        Patch::Set(changes) => {
            let sources = loaded
                .source_contents
                .values()
                .map(|source| {
                    toml::from_str::<toml::Value>(source).map_err(|_| {
                        ApiFailure::new(
                            hyper::StatusCode::CONFLICT,
                            "config_patch_not_atomic",
                            "Invalid independent policy source",
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut authored: HashMap<CidrRateLimitKey, Vec<String>> = HashMap::new();
            for source in &sources {
                if let Some(rows) = source
                    .get("access")
                    .and_then(|v| v.get("cidr_rate_limits"))
                    .and_then(toml::Value::as_table)
                {
                    for raw in rows.keys() {
                        authored
                            .entry(parse_key(raw)?)
                            .or_default()
                            .push(raw.clone());
                    }
                }
            }
            let mut seen = HashSet::new();
            for (key, rate) in changes {
                let parsed = parse_key(&key)?;
                if !seen.insert(parsed.clone()) {
                    return Err(ApiFailure::bad_request(
                        "Duplicate normalized CIDR policy key",
                    ));
                }
                let mut names = authored.remove(&parsed).unwrap_or_default();
                if names.len() > 1 {
                    return Err(ApiFailure::new(
                        hyper::StatusCode::CONFLICT,
                        "config_patch_not_atomic",
                        "CIDR policy key has ambiguous source ownership",
                    ));
                }
                let raw_key = names.pop().unwrap_or_else(|| parsed.to_string());
                let value = if let Some(rate) = rate {
                    let rate = RateLimitBps {
                        up_bps: rate.up_bps,
                        down_bps: rate.down_bps,
                    };
                    access.cidr_rate_limits.insert(parsed, rate);
                    Some(
                        toml::Value::try_from(rate)
                            .map_err(|_| ApiFailure::internal("Cannot render CIDR rate"))?,
                    )
                } else {
                    access.cidr_rate_limits.remove(&parsed);
                    None
                };
                edits.push(FieldEdit::new(
                    &["access", "cidr_rate_limits", &raw_key],
                    value,
                ));
            }
        }
    }
    if edits.is_empty() {
        return Err(ApiFailure::bad_request("Empty access policy patch"));
    }
    config.validate().map_err(|_| ApiFailure::bad_request("Access policy violates configuration constraints; rates require at least one positive direction, at most 100000000000 bps, and unique auto templates; window_secs must be positive"))?;
    Ok((config, edits))
}

pub(super) async fn read(shared: &ApiShared) -> Result<(PolicyState, String), ApiFailure> {
    let loaded = load_config_snapshot(&shared.config_path, false)
        .await
        .map_err(|_| ApiFailure::internal("Cannot load access policy source"))?;
    let fence = RuntimeFence::capture(shared, None)?;
    Ok((
        view(&loaded.config, &fence, None),
        compute_snapshot_revision(&loaded.source_contents),
    ))
}

pub(super) async fn patch(
    body: PolicyPatch,
    expected: Option<String>,
    runtime: Option<String>,
    shared: &ApiShared,
) -> Result<(PolicyState, String), ApiFailure> {
    let shared = shared.clone();
    shared
        .clone()
        .run_mutation_completion(async move {
            let _guard = shared.mutation_lock.lock().await;
            let fence = RuntimeFence::capture(&shared, runtime.as_deref())?;
            let path = shared.config_path.clone();
            let (loaded, desired, owned, changed) = tokio::task::spawn_blocking(move || {
                let loaded = ProxyConfig::parse_source(&path)
                    .map_err(|_| ApiFailure::internal("Cannot load access policy source"))?;
                let revision = compute_snapshot_revision(&loaded.source_contents);
                if expected.is_some_and(|value| value != revision) {
                    return Err(ApiFailure::new(
                        hyper::StatusCode::CONFLICT,
                        "revision_conflict",
                        "Config revision mismatch",
                    ));
                }
                let (desired, edits) = apply(&loaded, body)?;
                let owned = prepare_field_edits(&loaded, &path, &edits)?;
                // Project only the five public policy fields, off the async executor.
                let projection = |config: &ProxyConfig| {
                    serde_json::to_value(BTreeMap::from([("access", Policy::from(&config.access))]))
                        .map_err(|_| ApiFailure::internal("Cannot project access policy"))
                };
                let changed = super::config_projection::changed_paths(
                    &projection(&loaded.config)?,
                    &projection(&desired)?,
                );
                Ok::<_, ApiFailure>((loaded, desired, owned, changed))
            })
            .await
            .map_err(|_| ApiFailure::internal("Policy preparation worker failed"))??;
            let base_revision = compute_snapshot_revision(&loaded.source_contents);
            let revision = if let Some(owned) = owned {
                let candidate = load_candidate_snapshot(
                    &shared.config_path,
                    &loaded.source_contents,
                    owned.owner_path.clone(),
                    owned.owner_contents.clone(),
                )
                .await
                .map_err(|error| {
                    ApiFailure::new(
                        error.status,
                        error.code,
                        "Cannot prepare access policy candidate",
                    )
                })?;
                if Policy::from(&candidate.config.access) != Policy::from(&desired.access) {
                    return Err(ApiFailure::internal(
                        "Persisted policy candidate differs from requested policy",
                    ));
                }
                fence.ensure_current()?;
                write_atomic_with_runtime_check(
                    shared.config_path.clone(),
                    base_revision,
                    owned.owner_path,
                    owned.expected_owner_contents,
                    owned.owner_contents,
                    Some(fence.commit_check()),
                )
                .await?
            } else {
                fence.ensure_current()?;
                base_revision
            };
            shared.runtime_events.record(
                "api.access.policy.patch.ok",
                format!("changed_paths={}", changed.len()),
            );
            Ok((view(&desired, &fence, Some(changed)), revision))
        })
        .await
}

#[cfg(test)]
mod tests;
