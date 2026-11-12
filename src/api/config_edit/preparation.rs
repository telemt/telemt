//! One source-preserving candidate pipeline shared by preview and commit.
use super::*;
use crate::api::config_store::{FieldEdit, prepare_field_edits};
use crate::config::{LoadedConfig, ParsedConfigSource};
use tokio::sync::OwnedSemaphorePermit;

pub(super) type PreparationLease = Arc<Option<OwnedSemaphorePermit>>;

struct PatchSource {
    config_path: PathBuf,
    expected_revision: String,
    owner_path: PathBuf,
    expected_owner_contents: String,
    owner_contents: String,
    old_config: ProxyConfig,
    requested_config: ProxyConfig,
    patch: Json,
    touched: Vec<String>,
    alias_effects: Vec<diagnostics::NormalizationEffect>,
}

pub(super) async fn prepare_patch_to_path(
    config_path: &Path,
    patch: &Json,
    expected: Option<String>,
) -> Result<PreparedConfigPatch, ApiFailure> {
    prepare_guarded(config_path, patch, expected, Arc::new(None)).await
}

pub(super) async fn prepare_guarded(
    config_path: &Path,
    patch: &Json,
    expected: Option<String>,
    guard: PreparationLease,
) -> Result<PreparedConfigPatch, ApiFailure> {
    let config_path = config_path.to_path_buf();
    let patch = patch.clone();
    let worker_guard = guard.clone();
    let (source, details) = tokio::task::spawn_blocking(move || {
        let _guard = worker_guard;
        parse_patch(&config_path, &patch, expected)
    })
    .await
    .map_err(|_| ApiFailure::internal("Candidate source worker failed"))??;
    let candidate = source
        .prepare_guarded(guard.clone())
        .await
        .map_err(|error| {
            diagnostics::validation_error("preparation_failed", "web.vhosts[].decoy", error)
        })?;
    tokio::task::spawn_blocking(move || finish(details, candidate, guard))
        .await
        .map_err(|_| ApiFailure::internal("Candidate classification worker failed"))?
}

fn parse_patch(
    config_path: &Path,
    patch_json: &Json,
    expected_revision: Option<String>,
) -> Result<(ParsedConfigSource, PatchSource), ApiFailure> {
    // 1. optimistic concurrency
    let loaded = ProxyConfig::parse_source(config_path)
        .map_err(|error| diagnostics::validation_error("source_load_failed", "$", error))?;
    let current = compute_snapshot_revision(&loaded.source_contents);
    if expected_revision.is_some_and(|expected| expected != current) {
        return Err(ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "revision_conflict",
            "Config revision mismatch",
        ));
    }

    // 2. Reject access, unknown sections and forbidden partial-section fields.
    let mut patch_toml = json_to_toml(patch_json)
        .map_err(|e| ApiFailure::bad_request(format!("invalid patch: {}", e)))?;
    let patch_table = patch_toml
        .as_table()
        .ok_or_else(|| ApiFailure::bad_request("patch must be a JSON object"))?;
    if patch_table.contains_key("access") {
        return Err(ApiFailure::new(
            hyper::StatusCode::BAD_REQUEST,
            "access_not_editable",
            "access.* is managed via the users API, not editable here",
        ));
    }
    for key in patch_table.keys() {
        if !is_editable_section(key.as_str()) {
            return Err(ApiFailure::new(
                hyper::StatusCode::BAD_REQUEST,
                "section_not_editable",
                format!("section not editable: {}", key),
            ));
        }
        if key == "server" {
            validate_server_patch(&patch_json["server"])?;
        } else if key == "network" {
            validate_network_patch(&patch_json["network"])?;
        }
    }
    let touched: Vec<String> = patch_table
        .keys()
        .map(|k| k.as_str())
        .filter(|k| is_editable_section(k))
        .map(str::to_owned)
        .collect();
    if touched.is_empty() {
        return Err(ApiFailure::bad_request("empty patch: no editable sections"));
    }

    diagnostics::reject_unknown(patch_json)?;
    let alias_effects = diagnostics::canonicalize_aliases(&mut patch_toml)?;

    // 3. Merge against the fully expanded and normalized desired config. The
    // source owner is resolved separately so included sections stay in their
    // original file and unrelated source files remain byte-identical.
    let old_cfg = loaded.config.clone();
    let mut merged = Toml::try_from(&old_cfg)
        .map_err(|e| ApiFailure::internal(format!("failed to serialize config: {}", e)))?;
    deep_merge(&mut merged, &patch_toml);
    ProxyConfig::validate_decoy_source_keys(&merged)
        .map_err(|error| diagnostics::validation_error("constraint_violation", "$", error))?;

    let requested_cfg: ProxyConfig = merged
        .clone()
        .try_into()
        .map_err(|error| diagnostics::validation_error("deserialization_failed", "$", error))?;
    requested_cfg
        .validate()
        .map_err(|error| diagnostics::validation_error("constraint_violation", "$", error))?;

    let api_edits = api_field_edits(&loaded, &patch_toml)?;
    let api_source = prepare_field_edits(&loaded, config_path, &api_edits)
        .map_err(diagnostics::source_conflict)?;
    let patch_listeners = patch_toml
        .get("server")
        .is_some_and(|server| server.get("listeners").is_some());
    let ownership_targets: Vec<&str> = touched
        .iter()
        .filter_map(|section| {
            if section == "server" {
                patch_listeners.then_some("server.listeners")
            } else if section == "network" {
                Some("network.dns_overrides")
            } else {
                Some(section.as_str())
            }
        })
        .collect();
    let section_owner = if ownership_targets.is_empty() {
        None
    } else {
        Some(
            resolve_single_source_owner(&loaded, config_path, &ownership_targets)
                .map_err(diagnostics::source_conflict)?,
        )
    };
    if let (Some(owner), Some(api)) = (&section_owner, &api_source) {
        if *owner != api.owner_path {
            return Err(ApiFailure::new(
                hyper::StatusCode::CONFLICT,
                "config_patch_not_atomic",
                "Mutation requires one independently writable config source",
            ));
        }
    }
    let owner_path = section_owner
        .or_else(|| api_source.as_ref().map(|source| source.owner_path.clone()))
        .ok_or_else(|| ApiFailure::bad_request("empty patch: no editable fields"))?;
    let mut owner_contents = loaded
        .source_contents
        .get(&owner_path)
        .cloned()
        .ok_or_else(|| ApiFailure::internal("config source owner is missing from snapshot"))?;
    let expected_owner_contents = owner_contents.clone();
    if let Some(api) = api_source {
        owner_contents = api.owner_contents;
    }
    for section in &touched {
        if *section == "server" {
            if patch_listeners {
                let rendered = render_server_listeners(&requested_cfg)?;
                owner_contents = upsert_toml_table(&owner_contents, "server.listeners", &rendered);
            }
        } else if *section == "network" {
            owner_contents =
                upsert_dns_overrides(&owner_contents, &requested_cfg.network.dns_overrides)?;
        } else {
            let rendered = render_top_level_section(&requested_cfg, section)?;
            owner_contents = upsert_toml_table(&owner_contents, section, &rendered);
        }
    }

    let mut overrides = loaded.source_contents.clone();
    overrides.insert(owner_path.clone(), owner_contents.clone());
    let candidate = ProxyConfig::parse_source_with_overrides(config_path, &overrides)
        .map_err(|error| diagnostics::validation_error("constraint_violation", "$", error))?;
    if patch_listeners
        && serde_json::to_value(&candidate.config.server.listeners).ok()
            != serde_json::to_value(&requested_cfg.server.listeners).ok()
    {
        return Err(ApiFailure::new(
            hyper::StatusCode::BAD_REQUEST,
            "ambiguous_listeners",
            "server.listeners normalizes to a different effective listener set",
        ));
    }
    Ok((
        candidate,
        PatchSource {
            config_path: config_path.to_path_buf(),
            expected_revision: current,
            owner_path,
            expected_owner_contents,
            owner_contents,
            old_config: old_cfg,
            requested_config: requested_cfg,
            patch: patch_json.clone(),
            touched,
            alias_effects,
        },
    ))
}

fn api_field_edits(
    loaded: &ParsedConfigSource,
    patch: &Toml,
) -> Result<Vec<FieldEdit>, ApiFailure> {
    let Some(fields) = patch
        .get("server")
        .and_then(|server| server.get("api"))
        .and_then(Toml::as_table)
    else {
        return Ok(Vec::new());
    };
    if fields.is_empty() {
        return Ok(Vec::new());
    }
    // PATCH uses canonical paths, while an authored legacy table keeps its name.
    let mut table_name = "api";
    for source in loaded.source_contents.values() {
        let document: Toml = toml::from_str(source).map_err(|_| {
            ApiFailure::new(
                hyper::StatusCode::CONFLICT,
                "config_patch_not_atomic",
                "Mutation requires one independently writable config source",
            )
        })?;
        if document
            .get("server")
            .and_then(|server| server.get("admin_api"))
            .is_some()
        {
            table_name = "admin_api";
        }
    }
    Ok(fields
        .iter()
        .map(|(field, value)| FieldEdit::new(&["server", table_name, field], Some(value.clone())))
        .collect())
}

fn finish(
    source: PatchSource,
    candidate: LoadedConfig,
    guard: PreparationLease,
) -> Result<PreparedConfigPatch, ApiFailure> {
    let revision = compute_snapshot_revision(&candidate.source_contents);
    let new_config = candidate.config;
    let class = classify_config_changes(&source.old_config, &new_config);
    let deferred_process_fields = deferred_process_fields(&source.old_config, &new_config)
        .map_err(|error| diagnostics::validation_error("effective_config_invalid", "web", error))?;
    let old = serde_json::to_value(&source.old_config)
        .map_err(|_| ApiFailure::internal("Cannot project source fields"))?;
    let new = serde_json::to_value(&new_config)
        .map_err(|_| ApiFailure::internal("Cannot project candidate fields"))?;
    let changed_paths = diagnostics::changed_paths(&old, &new);
    let mut normalization_effects =
        diagnostics::normalization(&source.patch, &source.requested_config, &new_config)?;
    normalization_effects.extend(source.alias_effects);
    if changed_paths.len() > diagnostics::MAX_PATHS
        || normalization_effects.len() > diagnostics::MAX_PATHS
    {
        return Err(ApiFailure::bad_request(
            "Mutation exceeds the 4096-path feedback limit",
        ));
    }
    Ok(PreparedConfigPatch {
        config_path: source.config_path,
        expected_revision: source.expected_revision,
        owner_path: source.owner_path,
        expected_owner_contents: source.expected_owner_contents,
        owner_contents: source.owner_contents,
        desired_config: Arc::new(new_config),
        touched: source.touched,
        _guard: guard,
        response: PatchConfigResponse {
            revision,
            restart_required: class.restart_required,
            runtime_reload_required: class.restart_required,
            process_restart_required: !deferred_process_fields.is_empty(),
            deferred_process_fields,
            changed: class.changed,
            changed_paths,
            normalization_effects,
            reload: None,
        },
    })
}
