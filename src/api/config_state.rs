//! Bounded inspection of desired source and actual owner publications.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Full;
use hyper::{Response, StatusCode, body::Bytes};
use serde::Serialize;
use serde_json::Value as Json;

use super::config_edit::{RuntimeBaseline, RuntimeFence};
use super::model::{ApiFailure, FieldIssue};
use super::{ApiShared, config_projection as projection};
use crate::config::{
    ProxyConfig,
    observation::{ConfigProvenance, WatchOutcome},
};
use crate::maestro::{reload::ReloadObservation, runtime_build::project_reload_config};

const MAX_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_STATE_PATHS: usize = 512;

#[derive(Debug, Serialize)]
struct Comparison {
    scope: &'static str,
    status: &'static str,
    pending_paths: Vec<String>,
    watcher_pending_paths: Vec<String>,
    generation_pending_paths: Vec<String>,
    process_deferred_paths: Vec<String>,
    deferred_process_fields: Vec<String>,
    runtime_derived_paths: Vec<String>,
    truncated: bool,
}

impl Default for Comparison {
    fn default() -> Self {
        Self {
            scope: "selected_sections",
            status: "unknown",
            pending_paths: Vec::new(),
            watcher_pending_paths: Vec::new(),
            generation_pending_paths: Vec::new(),
            process_deferred_paths: Vec::new(),
            deferred_process_fields: Vec::new(),
            runtime_derived_paths: Vec::new(),
            truncated: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct ConfigState {
    scope: &'static str,
    sections: BTreeSet<String>,
    runtime: RuntimeBaseline,
    runtime_sample_current: bool,
    pub(super) desired_revision: Option<String>,
    desired_status: &'static str,
    desired_error: Option<FieldIssue>,
    desired: Option<projection::Projection>,
    effective: Option<projection::Projection>,
    projection_error: Option<FieldIssue>,
    comparison: Comparison,
    watcher: Option<WatchOutcome>,
    watcher_matches_desired: Option<bool>,
    reload: Option<ReloadObservation>,
    reload_observation: &'static str,
    reload_matches_desired: Option<bool>,
    subsystem_convergence: &'static str,
}

fn issue(code: &'static str, message: &'static str) -> FieldIssue {
    FieldIssue {
        path: "$".into(),
        code,
        message: message.into(),
    }
}

fn sections(query: Option<&str>) -> Result<BTreeSet<String>, ApiFailure> {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return Ok(projection::SECTIONS
            .iter()
            .map(|section| (*section).to_owned())
            .collect());
    };
    if query.len() > 256 {
        return Err(ApiFailure::bad_request(
            "Config state query exceeds 256 bytes",
        ));
    }
    let mut parsed = url::form_urlencoded::parse(query.as_bytes());
    let Some((key, value)) = parsed.next() else {
        return Err(ApiFailure::bad_request("Expected sections query"));
    };
    if key != "sections" || parsed.next().is_some() {
        return Err(ApiFailure::bad_request(
            "Only one sections query parameter is supported",
        ));
    }
    let mut sections = BTreeSet::new();
    for section in value.split(',') {
        if !projection::SECTIONS.contains(&section) || !sections.insert(section.to_owned()) {
            return Err(ApiFailure::bad_request(
                "Unknown, empty or repeated configuration section",
            ));
        }
    }
    Ok(sections)
}

fn json(config: &ProxyConfig) -> Result<Json, ApiFailure> {
    serde_json::to_value(config)
        .map_err(|_| ApiFailure::internal("Cannot project configuration snapshot"))
}

struct Desired {
    revision: Option<String>,
    status: &'static str,
    error: Option<FieldIssue>,
    projection: Option<projection::Projection>,
    effective: Option<projection::Projection>,
    comparison: Comparison,
}

fn unavailable(revision: Option<String>, status: &'static str, code: &'static str) -> Desired {
    Desired {
        revision,
        status,
        error: Some(issue(
            code,
            "Desired configuration is unavailable; effective publication remains readable",
        )),
        projection: None,
        effective: None,
        comparison: Comparison::default(),
    }
}

fn read_desired(
    path: &std::path::Path,
    active: &ProxyConfig,
    sections: &BTreeSet<String>,
) -> Result<Desired, ApiFailure> {
    let graph = match ProxyConfig::read_source_graph(path) {
        Ok(graph) => graph,
        Err(_) => return Ok(unavailable(None, "unreadable", "desired_source_unreadable")),
    };
    let revision = super::config_store::compute_source_revision(&graph);
    let mut desired = match ProxyConfig::parse_captured_source(graph) {
        Ok(parsed) => parsed.config,
        Err(_) => {
            return Ok(unavailable(
                Some(revision),
                "invalid",
                "desired_config_invalid",
            ));
        }
    };
    let mut derived = Vec::new();
    if matches!(&desired.provenance, ConfigProvenance::Source(source) if source.generated_fake_cert_len)
    {
        desired.censorship.fake_cert_len = active.censorship.fake_cert_len;
        if projection::selected("censorship.fake_cert_len", sections) {
            derived.push("censorship.fake_cert_len".into());
        }
    }
    let mut active_json = json(active)?;
    let mut desired_json = json(&desired)?;
    let effective =
        projection::project(active, &active_json, Some(&desired_json), sections, false)?;
    let desired_projection =
        projection::project(&desired, &desired_json, Some(&active_json), sections, true)?;
    let hot = crate::config::hot_reload::overlay_hot_fields(active, &desired);
    let projected = project_reload_config(active, &desired);
    let mut hot_json = json(&hot)?;
    let mut projected_json = json(&projected.effective)?;
    for value in [
        &mut active_json,
        &mut desired_json,
        &mut hot_json,
        &mut projected_json,
    ] {
        projection::retain_sections(value, sections);
    }
    let mut comparison = Comparison {
        pending_paths: projection::changed_paths(&active_json, &desired_json),
        watcher_pending_paths: projection::changed_paths(&active_json, &hot_json),
        generation_pending_paths: projection::changed_paths(&hot_json, &projected_json),
        process_deferred_paths: projection::changed_paths(&projected_json, &desired_json),
        deferred_process_fields: projected
            .deferred_process_fields
            .into_iter()
            .filter(|path| projection::selected(path, sections))
            .collect(),
        runtime_derived_paths: derived,
        ..Comparison::default()
    };
    comparison.status = if comparison.pending_paths.is_empty() {
        "published_match"
    } else if comparison.watcher_pending_paths.is_empty()
        && comparison.generation_pending_paths.is_empty()
    {
        "process_deferred"
    } else {
        "pending_publication"
    };
    for paths in [
        &mut comparison.pending_paths,
        &mut comparison.watcher_pending_paths,
        &mut comparison.generation_pending_paths,
        &mut comparison.process_deferred_paths,
    ] {
        comparison.truncated |= paths.len() > MAX_STATE_PATHS;
        paths.truncate(MAX_STATE_PATHS);
    }
    Ok(Desired {
        revision: Some(revision),
        status: "valid",
        error: None,
        projection: Some(desired_projection),
        effective: Some(effective),
        comparison,
    })
}

pub(super) async fn state(
    shared: &ApiShared,
    query: Option<&str>,
) -> Result<ConfigState, ApiFailure> {
    let sections = sections(query)?;
    let fence = RuntimeFence::capture(shared, None)?;
    let mut data = ConfigState {
        scope: "published_configuration_not_subsystem_acknowledgment",
        sections: sections.clone(),
        runtime: fence.baseline(),
        runtime_sample_current: true,
        desired_revision: None,
        desired_status: "busy",
        desired_error: None,
        desired: None,
        effective: None,
        projection_error: None,
        comparison: Comparison::default(),
        watcher: None,
        watcher_matches_desired: None,
        reload: None,
        reload_observation: "unknown",
        reload_matches_desired: None,
        subsystem_convergence: "unknown",
    };
    if let Ok(permit) = shared.config_state_slots.clone().try_acquire_owned() {
        let permit = Arc::new(permit);
        let guard = permit.clone();
        let active = fence.config.clone();
        let scope = sections.clone();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let effective = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            projection::project(&active, &json(&active)?, None, &scope, false)
        });
        match tokio::time::timeout_at(deadline, effective).await {
            Ok(Ok(Ok(effective))) => data.effective = Some(effective),
            _ => {
                data.projection_error = Some(issue(
                    "effective_projection_unavailable",
                    "Runtime identity is available but its projection could not complete",
                ))
            }
        }
        if data.effective.is_some() {
            let active = fence.config.clone();
            let path = shared.config_path.clone();
            let desired = tokio::task::spawn_blocking(move || {
                let _guard = permit;
                read_desired(&path, &active, &sections)
            });
            let desired = match tokio::time::timeout_at(deadline, desired).await {
                Ok(Ok(Ok(desired))) => desired,
                Ok(_) => unavailable(None, "unavailable", "desired_projection_failed"),
                Err(_) => unavailable(None, "timeout", "desired_read_timeout"),
            };
            data.desired_revision = desired.revision;
            data.desired_status = desired.status;
            data.desired_error = desired.error;
            data.desired = desired.projection;
            if desired.effective.is_some() {
                data.effective = desired.effective;
            }
            data.comparison = desired.comparison;
        } else {
            data.desired_status = "unavailable";
            data.desired_error = Some(issue(
                "state_projection_unavailable",
                "Configuration projection could not complete within the read budget",
            ));
        }
    } else {
        data.desired_error = Some(issue(
            "config_state_busy",
            "Both configuration inspection slots are occupied",
        ));
    }
    data.runtime_sample_current = fence.ensure_current().is_ok();
    data.watcher = fence
        .config
        .watcher_observation
        .as_ref()
        .and_then(|observer| observer.snapshot())
        .map(|outcome| (*outcome).clone());
    data.watcher_matches_desired = data.desired_revision.as_ref().and_then(|revision| {
        data.watcher
            .as_ref()?
            .source_revision
            .as_ref()
            .map(|source| source == revision)
    });
    match shared.reload_control.observation() {
        Some(reload) => {
            data.reload = reload;
            data.reload_observation = "sampled";
        }
        None => data.reload_observation = "busy",
    }
    data.reload_matches_desired = data.desired_revision.as_ref().and_then(|revision| {
        data.reload
            .as_ref()
            .map(|reload| &reload.source_revision == revision)
    });
    Ok(data)
}

pub(super) async fn response(
    shared: &ApiShared,
    query: Option<&str>,
) -> Result<Response<Full<Bytes>>, ApiFailure> {
    let mut data = state(shared, query).await?;
    loop {
        let body = serde_json::to_vec(
            &serde_json::json!({"ok": true, "revision": data.desired_revision, "data": data}),
        )
        .map_err(|_| ApiFailure::internal("Cannot encode configuration state"))?;
        if body.len() <= MAX_RESPONSE_BYTES {
            return Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json; charset=utf-8")
                .body(Full::new(Bytes::from(body)))
                .map_err(|_| ApiFailure::internal("Cannot build configuration state response"));
        }
        // Each list was already capped. Shrinking the two projections guarantees
        // that oversized deployment shapes cannot exceed the response envelope.
        let mut shrunk = false;
        for projection in [&mut data.desired, &mut data.effective]
            .into_iter()
            .flatten()
        {
            shrunk |= !projection.fields.is_empty();
            projection.fields.truncate(projection.fields.len() / 2);
            projection.truncated = true;
        }
        if !shrunk {
            return Err(ApiFailure::internal(
                "Configuration state metadata exceeded the response bound",
            ));
        }
    }
}

#[cfg(test)]
mod tests;
