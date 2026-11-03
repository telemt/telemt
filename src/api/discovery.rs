//! Read-only discovery of implemented operations and configuration contracts.
//!
//! Field defaults come from unconfigured types, never the active or disk config.
//! Availability samples only existing control-plane publications without waiting.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use crate::config::ProxyConfig;
use crate::web::control::WebRuntimeLifecycle;

use super::ApiShared;
use super::model::ApiFailure;

#[cfg(test)]
pub(in crate::api) mod http_tests;
mod schema;
#[cfg(test)]
mod tests;

pub(super) use schema::config_schema;

pub(super) fn config_field_paths() -> Result<Vec<&'static str>, ApiFailure> {
    schema::field_paths()
}

pub(super) use schema::projection_rules;

pub(super) const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Operation {
    pub(super) id: String,
    pub(super) method: String,
    pub(super) path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(super) aliases: Vec<String>,
    pub(super) gate: Gate,
    pub(super) success: Vec<u16>,
    #[serde(default)]
    pub(super) credential_bearing: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) body: Option<String>,
    #[serde(default)]
    pub(super) optional_body: bool,
    #[serde(default)]
    pub(super) exact_json_content_type: bool,
    #[serde(default)]
    pub(super) if_match: bool,
    #[serde(default)]
    pub(super) if_runtime_match: bool,
    #[serde(default)]
    pub(super) read_only_operation: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Gate {
    Always,
    Minimal,
    MinimalMe,
    MiddleProxy,
    Upstream,
    Edge,
    WebRead,
    WebControl,
}

pub(super) fn operations() -> Result<&'static [Operation], ApiFailure> {
    static CATALOG: OnceLock<Result<Vec<Operation>, String>> = OnceLock::new();
    CATALOG
        .get_or_init(|| {
            serde_json::from_str(include_str!("discovery/operations.json"))
                .map_err(|error| format!("invalid compiled operation catalog: {error}"))
        })
        .as_deref()
        .map_err(|error| ApiFailure::internal(error.clone()))
}

#[derive(Serialize)]
pub(super) struct CapabilitiesData {
    api_version: &'static str,
    schema_version: u32,
    software_version: &'static str,
    config_schema: &'static str,
    openapi_artifact: &'static str,
    read_only: bool,
    availability_scope: &'static str,
    operations: Vec<OperationCapability>,
}

#[derive(Serialize)]
struct OperationCapability {
    #[serde(flatten)]
    operation: &'static Operation,
    supported: bool,
    enabled: bool,
    /// Null means an optional runtime source was not sampled or its lock was busy.
    available: Option<bool>,
    mutable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mutation_blocked_reason: Option<&'static str>,
}

#[derive(Clone, Copy)]
pub(super) struct Availability {
    pub(super) me_pool: Option<bool>,
    pub(super) web_read: bool,
    pub(super) web_control: bool,
}

pub(super) fn capabilities(
    shared: &ApiShared,
    config: &ProxyConfig,
) -> Result<CapabilitiesData, ApiFailure> {
    let me_pool = shared.me_pool.try_read().ok().map(|pool| pool.is_some());
    let availability = {
        let publication = shared.web_runtime_rx.borrow();
        let web_alive = publication.runtime.upgrade().is_some();
        Availability {
            me_pool,
            web_read: web_alive
                && matches!(
                    publication.lifecycle,
                    WebRuntimeLifecycle::Running | WebRuntimeLifecycle::Draining
                ),
            web_control: web_alive && publication.lifecycle == WebRuntimeLifecycle::Running,
        }
    };
    build_capabilities(config, availability)
}

fn build_capabilities(
    config: &ProxyConfig,
    availability: Availability,
) -> Result<CapabilitiesData, ApiFailure> {
    let mut entries = Vec::with_capacity(operations()?.len());
    for operation in operations()? {
        let feature_enabled = match operation.gate {
            Gate::Minimal | Gate::MinimalMe => config.server.api.minimal_runtime_enabled,
            Gate::Edge => config.server.api.runtime_edge_enabled,
            _ => true,
        };
        let enabled = config.server.api.enabled && feature_enabled;
        let (available, unavailable_reason) = if !enabled {
            (Some(false), None)
        } else {
            match operation.gate {
                Gate::MinimalMe | Gate::MiddleProxy => match availability.me_pool {
                    Some(true) => (Some(true), None),
                    Some(false) => (Some(false), Some("source_unavailable")),
                    None => (None, Some("snapshot_busy")),
                },
                Gate::WebRead if !availability.web_read => {
                    (Some(false), Some("web_runtime_unavailable"))
                }
                Gate::WebControl if !availability.web_control => {
                    (Some(false), Some("web_runtime_unavailable"))
                }
                // These handlers perform their own bounded aggregation. Discovery
                // does not repeat it or claim a sampled health/lock result.
                Gate::Minimal | Gate::Upstream => (None, Some("availability_not_sampled")),
                Gate::Edge if operation.id == "runtime_connections_summary" => {
                    (None, Some("availability_not_sampled"))
                }
                _ => (Some(true), None),
            }
        };
        let mutation = operation.method != "GET" && !operation.read_only_operation;
        entries.push(OperationCapability {
            operation,
            supported: true,
            enabled,
            available,
            mutable: mutation && config.server.api.enabled && !config.server.api.read_only,
            disabled_reason: if !config.server.api.enabled {
                Some("api_disabled")
            } else if !feature_enabled {
                Some("feature_disabled")
            } else {
                None
            },
            unavailable_reason,
            mutation_blocked_reason: if mutation && config.server.api.read_only {
                Some("read_only")
            } else {
                None
            },
        });
    }
    Ok(CapabilitiesData {
        api_version: "v1",
        schema_version: SCHEMA_VERSION,
        software_version: env!("CARGO_PKG_VERSION"),
        config_schema: "/v1/config/schema",
        openapi_artifact: "docs/Architecture/API/openapi-v1.json",
        read_only: config.server.api.read_only,
        availability_scope: "feature_and_runtime_source_prerequisites_not_request_success",
        operations: entries,
    })
}

pub(super) fn reject_query(query: Option<&str>) -> Result<(), ApiFailure> {
    if query.is_some_and(|query| !query.is_empty()) {
        return Err(ApiFailure::bad_request(
            "discovery endpoints do not accept query parameters",
        ));
    }
    Ok(())
}
