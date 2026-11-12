//! Config-editing API: read managed sections and apply sparse field patches.
//! `access.*` is intentionally not editable here (owned by the users API).
//! `[server]` is only partially editable — see [`EDITABLE_SERVER_FIELDS`].
//! `[network]` exposes only [`EDITABLE_NETWORK_FIELDS`].

use serde_json::Value as Json;
use toml::Value as Toml;

use super::ApiShared;
use super::config_store::{
    EDITABLE_NETWORK_FIELDS, EDITABLE_SECTIONS, EDITABLE_SERVER_API_FIELDS, EDITABLE_SERVER_FIELDS,
    compute_snapshot_revision, is_editable_section, load_config_snapshot, render_server_listeners,
    render_top_level_section, resolve_single_source_owner, upsert_dns_overrides, upsert_toml_table,
};
#[cfg(test)]
use super::config_store::{write_atomic, write_atomic_if_unchanged};
use super::model::ApiFailure;
use crate::config::ProxyConfig;
use crate::config::hot_reload::classify_config_changes;
use crate::maestro::reload::{ReloadAccepted, ReloadRequest, ReloadSubmitError};
use crate::maestro::runtime_build::{
    ResolvedReloadConfig, deferred_process_fields, resolve_reload_config,
};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(test)]
mod api_observability_tests;
mod diagnostics;
mod preflight;
mod preparation;
pub(super) use preflight::{RuntimeBaseline, RuntimeFence};
pub(super) use preflight::{parse_runtime_match, validate_config};
use preparation::prepare_patch_to_path;

/// Result of one validated managed-config mutation.
#[derive(Debug, Serialize)]
pub(super) struct PatchConfigResponse {
    /// Revision of the persisted desired configuration.
    pub revision: String,
    /// Whether any changed field is not hot-reloadable.
    pub restart_required: bool,
    /// Whether the effective runtime snapshot must be reloaded.
    pub runtime_reload_required: bool,
    /// Whether any desired field remains deferred until process restart.
    pub process_restart_required: bool,
    /// Stable paths of desired fields retained from the active process.
    pub deferred_process_fields: Vec<String>,
    /// Top-level managed sections changed by the mutation.
    pub changed: Vec<String>,
    /// Canonical changed leaf paths, without configuration values.
    pub changed_paths: Vec<String>,
    pub normalization_effects: Vec<diagnostics::NormalizationEffect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Accepted runtime reload when one was requested and required.
    pub reload: Option<ReloadAccepted>,
}

struct PreparedConfigPatch {
    config_path: PathBuf,
    expected_revision: String,
    owner_path: PathBuf,
    expected_owner_contents: String,
    owner_contents: String,
    desired_config: Arc<ProxyConfig>,
    response: PatchConfigResponse,
    touched: Vec<String>,
    _guard: preparation::PreparationLease,
}

/// Serializes config mutations behind `mutation_lock`, commits them, and records
/// a runtime event. The route handler calls this shared-state wrapper.
pub(super) async fn patch_config(
    patch_json: Json,
    expected_revision: Option<String>,
    expected_runtime: Option<String>,
    reload_request: Option<ReloadRequest>,
    shared: &ApiShared,
) -> Result<PatchConfigResponse, ApiFailure> {
    let shared = shared.clone();
    shared
        .clone()
        .run_mutation_completion(async move {
            patch_config_to_completion(
                patch_json,
                expected_revision,
                expected_runtime,
                reload_request,
                &shared,
            )
            .await
        })
        .await
}

async fn patch_config_to_completion(
    patch_json: Json,
    expected_revision: Option<String>,
    expected_runtime: Option<String>,
    reload_request: Option<ReloadRequest>,
    shared: &ApiShared,
) -> Result<PatchConfigResponse, ApiFailure> {
    let _guard = shared.mutation_lock.lock().await;
    let fence = preflight::RuntimeFence::capture(shared, expected_runtime.as_deref())?;
    let prepared =
        prepare_patch_to_path(&shared.config_path, &patch_json, expected_revision).await?;
    let active_config = fence.config.clone();
    let (mut prepared, resolved) = tokio::task::spawn_blocking(move || {
        let mut prepared = prepared;
        let resolved = reconcile_runtime_effect(
            &mut prepared.response,
            &active_config,
            &prepared.desired_config,
        )?;
        Ok::<_, ApiFailure>((prepared, resolved))
    })
    .await
    .map_err(|_| ApiFailure::internal("Mutation classification worker failed"))??;
    fence.ensure_current()?;
    let reservation = if let Some(request) = reload_request.filter(|_| resolved.runtime_changed) {
        Some(
            shared
                .reload_control
                .reserve(prepared.response.revision.clone(), request)
                .await
                .map_err(reload_submit_failure)?,
        )
    } else {
        None
    };
    prepared.response.revision = super::config_store::write_atomic_with_runtime_check(
        prepared.config_path,
        prepared.expected_revision,
        prepared.owner_path,
        prepared.expected_owner_contents,
        prepared.owner_contents,
        Some(fence.commit_check()),
    )
    .await?;
    if let Some(reservation) = reservation {
        prepared.response.reload = Some(reservation.enqueue(prepared.desired_config));
    }
    let resp = prepared.response;
    drop(_guard);
    shared
        .runtime_events
        .record("api.config.patch.ok", format!("changed={:?}", resp.changed));
    Ok(resp)
}

fn reconcile_runtime_effect(
    response: &mut PatchConfigResponse,
    active_config: &ProxyConfig,
    desired_config: &ProxyConfig,
) -> Result<ResolvedReloadConfig, ApiFailure> {
    let resolved = resolve_reload_config(active_config, desired_config)
        .map_err(|error| diagnostics::validation_error("effective_config_invalid", "web", error))?;
    response.runtime_reload_required = resolved.runtime_changed;
    response.process_restart_required = !resolved.deferred_process_fields.is_empty();
    response.deferred_process_fields = resolved.deferred_process_fields.clone();
    Ok(resolved)
}

/// Core patch logic, decoupled from hyper/shared-state so it is unit-testable
/// against a temp file. The route handler holds `mutation_lock` while calling this.
#[cfg(test)]
pub(super) async fn apply_patch_to_path(
    config_path: &Path,
    patch_json: &Json,
    expected_revision: Option<String>,
) -> Result<PatchConfigResponse, ApiFailure> {
    let mut prepared = prepare_patch_to_path(config_path, patch_json, expected_revision).await?;
    let revision = write_atomic_if_unchanged(
        prepared.config_path,
        prepared.expected_revision,
        prepared.owner_path,
        prepared.expected_owner_contents,
        prepared.owner_contents,
    )
    .await?;
    prepared.response.revision = revision;
    Ok(prepared.response)
}

fn reload_submit_failure(error: ReloadSubmitError) -> ApiFailure {
    match error {
        ReloadSubmitError::InProgress(reload_id) => ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "reload_in_progress",
            format!("Reload {} is already in progress", reload_id),
        ),
        ReloadSubmitError::MaestroUnavailable => ApiFailure::new(
            hyper::StatusCode::SERVICE_UNAVAILABLE,
            "maestro_unavailable",
            "Maestro reload coordinator is unavailable",
        ),
    }
}

/// Returns only the editable config sections and current revision.
pub(super) async fn read_managed_config(config_path: &Path) -> Result<(Toml, String), ApiFailure> {
    let loaded = load_config_snapshot(config_path, false).await?;
    let revision = compute_snapshot_revision(&loaded.source_contents);
    let parsed = Toml::try_from(&loaded.config)
        .map_err(|error| ApiFailure::internal(format!("failed to serialize config: {error}")))?;

    let parsed_table = parsed
        .as_table()
        .cloned()
        .unwrap_or_else(toml::value::Table::new);
    // Whitelist: return ONLY the editable sections. A blacklist (just removing
    // `access`) would leak `server.api` (auth_header) and `network` (per-node
    // addresses). Mirror the PATCH contract, including both nested allowlists.
    let mut table = toml::value::Table::new();
    for section in EDITABLE_SECTIONS {
        if let Some(value) = parsed_table.get(*section) {
            table.insert((*section).to_string(), value.clone());
        }
    }
    if let Some(server) = parsed_table.get("server") {
        if let Some(filtered) = filter_server_for_read(server) {
            table.insert("server".to_string(), filtered);
        }
    }
    if let Some(network) = parsed_table.get("network").and_then(Toml::as_table) {
        let filtered = network
            .iter()
            .filter(|(key, _)| EDITABLE_NETWORK_FIELDS.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        table.insert("network".to_owned(), Toml::Table(filtered));
    }

    Ok((Toml::Table(table), revision))
}

/// Keep only [`EDITABLE_SERVER_FIELDS`] from a `[server]` table for GET.
fn filter_server_for_read(server: &Toml) -> Option<Toml> {
    let Some(src) = server.as_table() else {
        return None;
    };
    let mut out = toml::value::Table::new();
    for field in EDITABLE_SERVER_FIELDS {
        if let Some(value) = src.get(*field) {
            // Skip empty listeners arrays so absent-vs-empty stays consistent
            // with other optional sections.
            if *field == "listeners" {
                if let Some(arr) = value.as_array() {
                    if arr.is_empty() {
                        continue;
                    }
                }
            }
            if *field == "api" {
                if let Some(api) = value.as_table() {
                    out.insert(
                        "api".to_owned(),
                        Toml::Table(
                            api.iter()
                                .filter(|(key, _)| {
                                    EDITABLE_SERVER_API_FIELDS.contains(&key.as_str())
                                })
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect(),
                        ),
                    );
                }
            } else {
                out.insert((*field).to_string(), value.clone());
            }
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(Toml::Table(out))
    }
}

/// Reject any `[server]` patch keys outside [`EDITABLE_SERVER_FIELDS`].
fn validate_server_patch(server: &Json) -> Result<(), ApiFailure> {
    let Some(table) = server.as_object() else {
        return Err(ApiFailure::new(
            hyper::StatusCode::BAD_REQUEST,
            "section_not_editable",
            "server patch must be a JSON object",
        ));
    };
    // Validate original keys before null removal, including forbidden siblings.
    for key in table.keys() {
        if !EDITABLE_SERVER_FIELDS.contains(&key.as_str()) {
            return Err(ApiFailure::new(
                hyper::StatusCode::BAD_REQUEST,
                "field_not_editable",
                format!(
                    "server.{} is not editable via the config API; allowed server fields: {}",
                    key,
                    EDITABLE_SERVER_FIELDS.join(", ")
                ),
            ));
        }
    }
    if let Some(api) = table.get("api").filter(|api| !api.is_null()) {
        let fields = api
            .as_object()
            .ok_or_else(|| ApiFailure::bad_request("server.api patch must be a JSON object"))?;
        for key in fields.keys() {
            if !EDITABLE_SERVER_API_FIELDS.contains(&key.as_str()) {
                return Err(ApiFailure::new(
                    hyper::StatusCode::BAD_REQUEST,
                    "field_not_editable",
                    format!("server.api.{key} is not editable via the config API"),
                ));
            }
        }
    }
    let has_listeners = table.get("listeners").is_some_and(|value| !value.is_null());
    let has_api_fields = table
        .get("api")
        .and_then(Json::as_object)
        .is_some_and(|fields| fields.values().any(|value| !value.is_null()));
    if !has_listeners && !has_api_fields {
        return Err(ApiFailure::bad_request(
            "empty server patch: provide listeners or an editable server.api field",
        ));
    }
    Ok(())
}

fn validate_network_patch(network: &Json) -> Result<(), ApiFailure> {
    let Some(table) = network.as_object() else {
        return Err(ApiFailure::new(
            hyper::StatusCode::BAD_REQUEST,
            "section_not_editable",
            "network patch must be a JSON object",
        ));
    };
    // Check the original keys so even a forbidden null member cannot bypass
    // the network allowlist during JSON-to-TOML null removal.
    for key in table.keys() {
        if !EDITABLE_NETWORK_FIELDS.contains(&key.as_str()) {
            return Err(ApiFailure::new(
                hyper::StatusCode::BAD_REQUEST,
                "field_not_editable",
                format!(
                    "network.{key} is not editable via the config API; allowed network fields: {}",
                    EDITABLE_NETWORK_FIELDS.join(", ")
                ),
            ));
        }
    }
    if table.values().all(Json::is_null) {
        return Err(ApiFailure::bad_request(
            "empty network patch: provide dns_overrides (use [] to clear)",
        ));
    }
    Ok(())
}

/// Convert a serde_json value to a toml value. `null` is dropped from objects
/// (a patch never sets a key to TOML-null). Numbers become integers when exact,
/// otherwise floats.
fn json_to_toml(j: &Json) -> Result<Toml, String> {
    Ok(match j {
        Json::Null => return Err("null is not representable in TOML".into()),
        Json::Bool(b) => Toml::Boolean(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Toml::Integer(i)
            } else if let Some(f) = n.as_f64() {
                Toml::Float(f)
            } else {
                return Err(format!("unrepresentable number: {}", n));
            }
        }
        Json::String(s) => Toml::String(s.clone()),
        Json::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(json_to_toml(item)?);
            }
            Toml::Array(out)
        }
        Json::Object(map) => {
            let mut table = toml::value::Table::new();
            for (k, v) in map {
                if v.is_null() {
                    // TOML has no null value, so sparse object nulls are omitted.
                    continue;
                }
                table.insert(k.clone(), json_to_toml(v)?);
            }
            Toml::Table(table)
        }
    })
}

/// Recursively overlay `patch` onto `base`. Tables merge key-by-key; every
/// other value type (scalars, arrays) replaces wholesale.
fn deep_merge(base: &mut Toml, patch: &Toml) {
    match (base, patch) {
        (Toml::Table(b), Toml::Table(p)) => {
            for (k, pv) in p {
                match b.get_mut(k) {
                    Some(bv) => deep_merge(bv, pv),
                    None => {
                        b.insert(k.clone(), pv.clone());
                    }
                }
            }
        }
        (b, p) => *b = p.clone(),
    }
}

#[cfg(test)]
#[path = "config_edit/base_path_tests.rs"]
mod base_path_tests;
#[cfg(test)]
#[path = "config_edit/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "config_edit/conveyor_tests.rs"]
mod conveyor_tests;

#[cfg(test)]
#[path = "config_edit/decoy_dns_tests.rs"]
mod decoy_dns_tests;

// Exact host groups retain the source shape and process-deferred limit checks.
#[cfg(test)]
mod host_list_tests;

#[cfg(test)]
mod quota_period_tests;

#[cfg(test)]
mod preflight_tests;

#[cfg(test)]
mod dns_overrides_tests;
