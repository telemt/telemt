use std::sync::OnceLock;
use std::time::Duration;

use crate::api::config_store::CommitCheck;
use crate::api::model::FieldIssue;
use crate::config::hot_reload::overlay_hot_fields;
use crate::maestro::generation::RuntimeGeneration;
use hyper::{HeaderMap, StatusCode};

use super::*;

#[derive(Debug, Serialize)]
pub(super) struct RuntimeBaseline {
    pub(super) active_generation: u64,
    pub(super) config_epoch: u64,
    pub(super) runtime_match: String,
}

#[derive(Clone)]
pub(super) struct RuntimeFence {
    active: Arc<arc_swap::ArcSwap<RuntimeGeneration>>,
    generation: Arc<RuntimeGeneration>,
    pub(super) config: Arc<ProxyConfig>,
}

impl RuntimeFence {
    pub(super) fn capture(shared: &ApiShared, expected: Option<&str>) -> Result<Self, ApiFailure> {
        let generation = shared.active_runtime.load_full();
        let config = generation.config();
        let fence = Self {
            active: shared.active_runtime.clone(),
            generation,
            config,
        };
        fence.ensure_current()?;
        if expected.is_some_and(|expected| expected != fence.baseline().runtime_match) {
            return Err(runtime_conflict());
        }
        Ok(fence)
    }

    pub(super) fn baseline(&self) -> RuntimeBaseline {
        static PROCESS: OnceLock<String> = OnceLock::new();
        let process = PROCESS.get_or_init(|| {
            let mut bytes = [0_u8; 16];
            crate::crypto::SecureRandom::new().fill(&mut bytes);
            hex::encode(bytes)
        });
        RuntimeBaseline {
            active_generation: self.generation.id,
            config_epoch: self.config.runtime_config_epoch,
            runtime_match: format!(
                "{process}:{}:{}",
                self.generation.id, self.config.runtime_config_epoch
            ),
        }
    }

    fn matches(&self) -> bool {
        let current = self.active.load_full();
        Arc::ptr_eq(&current, &self.generation)
            && Arc::ptr_eq(&current.config(), &self.config)
            && Arc::ptr_eq(&self.active.load_full(), &self.generation)
    }

    pub(super) fn ensure_current(&self) -> Result<(), ApiFailure> {
        if self.matches() {
            Ok(())
        } else {
            Err(runtime_conflict())
        }
    }

    pub(super) fn commit_check(&self) -> CommitCheck {
        let fence = self.clone();
        Arc::new(move || fence.matches())
    }
}

fn runtime_conflict() -> ApiFailure {
    let mut error = ApiFailure::new(
        StatusCode::CONFLICT,
        "runtime_conflict",
        "Runtime configuration changed; validate against a fresh baseline",
    );
    error.details.push(diagnostics::issue(
        "$",
        "runtime_conflict",
        error.message.clone(),
    ));
    error
}

pub(in crate::api) fn parse_runtime_match(
    headers: &HeaderMap,
) -> Result<Option<String>, ApiFailure> {
    let mut values = headers.get_all("if-runtime-match").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| ApiFailure::bad_request("Invalid If-Runtime-Match header"))?
        .trim()
        .trim_matches('"');
    if values.next().is_some()
        || value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
    {
        return Err(ApiFailure::bad_request("Invalid If-Runtime-Match header"));
    }
    Ok(Some(value.to_owned()))
}

#[derive(Debug, Serialize)]
pub(super) struct ApplyImpact {
    pub(super) watcher_paths: Vec<String>,
    pub(super) generation_paths: Vec<String>,
    pub(super) process_restart_paths: Vec<String>,
    pub(super) restart_required: bool,
    pub(super) runtime_reload_required: bool,
    pub(super) process_restart_required: bool,
    pub(super) deferred_process_fields: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(in crate::api) struct ValidationResponse {
    pub(super) valid: bool,
    pub(in crate::api) base_revision: String,
    pub(super) candidate_revision: String,
    pub(super) runtime: RuntimeBaseline,
    pub(super) changed_paths: Vec<String>,
    pub(super) normalization_effects: Vec<diagnostics::NormalizationEffect>,
    pub(super) apply: ApplyImpact,
    pub(super) source_ownership: &'static str,
    pub(super) touched_sections: Vec<String>,
    pub(super) reload: Option<ReloadRequest>,
    pub(super) warnings: Vec<FieldIssue>,
}

/// All blocking workers retain the same lease. Dropping this future cannot
/// publish data, reserve a reload, or let an abandoned worker bypass the budget.
pub(in crate::api) async fn validate_config(
    patch: Json,
    expected_revision: Option<String>,
    expected_runtime: Option<String>,
    reload: Option<ReloadRequest>,
    shared: &ApiShared,
) -> Result<ValidationResponse, ApiFailure> {
    if let Some(request) = &reload {
        request.validate().map_err(ApiFailure::bad_request)?;
    }
    let permit = shared
        .config_preflight_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            ApiFailure::new(
                StatusCode::TOO_MANY_REQUESTS,
                "config_preflight_busy",
                "Both configuration preparation slots are occupied",
            )
        })?;
    let guard = Arc::new(Some(permit));
    let fence = RuntimeFence::capture(shared, expected_runtime.as_deref())?;
    let preparation = async {
        let prepared =
            preparation::prepare_guarded(&shared.config_path, &patch, expected_revision, guard)
                .await?;
        let active = fence.config.clone();
        let (prepared, apply) = tokio::task::spawn_blocking(move || {
            let mut prepared = prepared;
            let resolved = reconcile_runtime_effect(
                &mut prepared.response,
                &active,
                &prepared.desired_config,
            )?;
            let hot = overlay_hot_fields(&active, &prepared.desired_config);
            let json = |config: &ProxyConfig| {
                serde_json::to_value(config)
                    .map_err(|_| ApiFailure::internal("Cannot project application paths"))
            };
            let active = json(&active)?;
            let hot = json(&hot)?;
            let effective = json(&resolved.effective)?;
            let desired = json(&prepared.desired_config)?;
            let apply = ApplyImpact {
                watcher_paths: diagnostics::changed_paths(&active, &hot),
                generation_paths: diagnostics::changed_paths(&hot, &effective),
                process_restart_paths: diagnostics::changed_paths(&effective, &desired),
                restart_required: prepared.response.restart_required,
                runtime_reload_required: prepared.response.runtime_reload_required,
                process_restart_required: prepared.response.process_restart_required,
                deferred_process_fields: prepared.response.deferred_process_fields.clone(),
            };
            if [
                &apply.watcher_paths,
                &apply.generation_paths,
                &apply.process_restart_paths,
            ]
            .into_iter()
            .any(|paths| paths.len() > diagnostics::MAX_PATHS)
            {
                return Err(ApiFailure::bad_request(
                    "Preview exceeds the 4096-path feedback limit",
                ));
            }
            // Keep the preparation lease in this worker through the final source
            // read, including when its awaiting HTTP request has been cancelled.
            let graph = ProxyConfig::read_source_graph(&prepared.config_path)
                .map_err(|error| diagnostics::validation_error("source_load_failed", "$", error))?;
            if compute_snapshot_revision(&graph.source_contents) != prepared.expected_revision {
                return Err(ApiFailure::new(
                    StatusCode::CONFLICT,
                    "revision_conflict",
                    "Config revision changed during validation",
                ));
            }
            Ok((prepared, apply))
        })
        .await
        .map_err(|_| ApiFailure::internal("Preview classification worker failed"))??;
        fence.ensure_current()?;
        let mut warnings = vec![diagnostics::issue(
            "$",
            "preparation_reads",
            "Preparation may read DNS and static assets; listener binding and runtime startup are not tested",
        )];
        if !apply.generation_paths.is_empty() && reload.is_none() {
            warnings.push(diagnostics::issue(
                "$",
                "reload_not_requested",
                "Generation-owned changes require an explicit reload",
            ));
        }
        if apply.process_restart_required {
            warnings.push(diagnostics::issue(
                "$",
                "process_restart_required",
                "Some desired fields remain deferred until process restart",
            ));
        }
        Ok(ValidationResponse {
            valid: true,
            base_revision: prepared.expected_revision,
            candidate_revision: prepared.response.revision,
            runtime: fence.baseline(),
            changed_paths: prepared.response.changed_paths,
            normalization_effects: prepared.response.normalization_effects,
            apply,
            source_ownership: "single_source",
            touched_sections: prepared.touched,
            reload,
            warnings,
        })
    };
    tokio::time::timeout(Duration::from_secs(30), preparation)
        .await
        .map_err(|_| {
            ApiFailure::new(
                StatusCode::GATEWAY_TIMEOUT,
                "config_preflight_timeout",
                "Configuration preparation exceeded 30 seconds",
            )
        })?
}
