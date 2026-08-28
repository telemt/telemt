use std::collections::BTreeSet;
use std::net::IpAddr;

use hyper::StatusCode;
use serde::Deserialize;

use crate::config::WebCarrier;
use crate::web::manager::{
    CloseOperationSelector, SessionFilter, SessionListRequest, SessionRefError, WebProcessRuntime,
};

use super::super::model::ApiFailure;

const DEFAULT_SESSION_LIMIT: usize = 50;
const MAX_SESSION_LIMIT: usize = 200;

/// Exact process-instance fence for one runtime mutation.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RuntimeInstanceRequest {
    /// Random process identifier copied from WEB runtime status.
    pub(super) runtime_instance: String,
}

/// Process-fenced graceful drain request with one bounded relative deadline.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DrainRequest {
    /// Random process identifier copied from WEB runtime status.
    pub(super) runtime_instance: String,
    /// Relative drain deadline frozen into one monotonic server deadline.
    pub(super) timeout_secs: u64,
}

/// One process-fenced asynchronous close request.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CloseRequest {
    /// Random process identifier copied from WEB runtime status.
    pub(super) runtime_instance: String,
    /// Exact point-in-time close selector.
    pub(super) selector: CloseSelectorRequest,
}

/// Strict tagged selector accepted by the WEB close endpoint.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CloseSelectorRequest {
    /// Closes an explicit bounded set of logical sessions.
    Refs {
        /// Unique current-instance opaque session references.
        session_refs: Vec<String>,
    },
    /// Closes the point-in-time sessions matching every supplied field.
    Filter {
        #[serde(default)]
        session_ref: Option<String>,
        #[serde(default)]
        ip: Option<String>,
        #[serde(default)]
        host: Option<String>,
        #[serde(default)]
        user: Option<String>,
        #[serde(default)]
        user_agent_id: Option<String>,
        #[serde(default)]
        key_id: Option<String>,
        #[serde(default)]
        carrier: Option<WebCarrier>,
        #[serde(default)]
        state: Option<String>,
    },
    /// Closes every point-in-time session below the submission high-water mark.
    All {},
}

impl CloseSelectorRequest {
    /// Validates external identifiers and resolves them to manager-owned values.
    pub(super) fn resolve(
        self,
        runtime: &WebProcessRuntime,
    ) -> Result<CloseOperationSelector, ApiFailure> {
        match self {
            Self::Refs { session_refs } => resolve_refs(runtime, session_refs),
            Self::Filter {
                session_ref,
                ip,
                host,
                user,
                user_agent_id,
                key_id,
                carrier,
                state,
            } => {
                validate_filter_strings(
                    host.as_deref(),
                    user.as_deref(),
                    key_id.as_deref(),
                    state.as_deref(),
                )?;
                let trace_session_id = session_ref
                    .as_deref()
                    .map(|value| parse_session_ref(runtime, value))
                    .transpose()?;
                let client_ip = ip.as_deref().map(parse_canonical_ip).transpose()?;
                let filter = SessionFilter {
                    trace_session_id,
                    client_ip,
                    host,
                    user,
                    user_agent_id: user_agent_id
                        .as_deref()
                        .map(parse_user_agent_id)
                        .transpose()?,
                    key_id,
                    carrier,
                    state,
                };
                if filter.is_empty() {
                    return Err(ApiFailure::bad_request(
                        "filter selector requires at least one filter",
                    ));
                }
                Ok(CloseOperationSelector::Filter(filter))
            }
            Self::All {} => Ok(CloseOperationSelector::All),
        }
    }
}

fn resolve_refs(
    runtime: &WebProcessRuntime,
    session_refs: Vec<String>,
) -> Result<CloseOperationSelector, ApiFailure> {
    if session_refs.is_empty() || session_refs.len() > 200 {
        return Err(ApiFailure::bad_request(
            "session_refs must contain 1..200 references",
        ));
    }
    let mut resolved = Vec::with_capacity(session_refs.len());
    let mut unique = BTreeSet::new();
    for session_ref in session_refs {
        let id = parse_session_ref(runtime, &session_ref)?;
        if !unique.insert(id) {
            return Err(ApiFailure::bad_request(
                "session_refs must not contain duplicates",
            ));
        }
        resolved.push(id);
    }
    Ok(CloseOperationSelector::Refs(resolved))
}

/// Parses one duplicate-free bounded session-list query.
pub(super) fn parse_session_query(
    runtime: &WebProcessRuntime,
    raw: Option<&str>,
) -> Result<SessionListRequest, ApiFailure> {
    let mut limit = DEFAULT_SESSION_LIMIT;
    let mut cursor = None;
    let mut filter = SessionFilter::default();
    let mut seen = BTreeSet::new();
    for (name, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
        if !seen.insert(name.to_string()) {
            return Err(ApiFailure::bad_request(format!("{} must not repeat", name)));
        }
        match name.as_ref() {
            "limit" => {
                limit = value
                    .parse::<usize>()
                    .ok()
                    .filter(|value| (1..=MAX_SESSION_LIMIT).contains(value))
                    .ok_or_else(|| ApiFailure::bad_request("limit must be within 1..200"))?;
            }
            "cursor" => cursor = Some(parse_session_ref(runtime, &value)?),
            "session_ref" => {
                let id = parse_session_ref(runtime, &value)?;
                filter.trace_session_id = Some(id);
                cursor = id.checked_sub(1);
                limit = 1;
            }
            "ip" => {
                filter.client_ip = Some(parse_canonical_ip(&value)?);
            }
            "host" => filter.host = Some(value.into_owned()),
            "user" => filter.user = Some(value.into_owned()),
            "user_agent_id" => filter.user_agent_id = Some(parse_user_agent_id(&value)?),
            "key_id" => filter.key_id = Some(value.into_owned()),
            "carrier" => filter.carrier = Some(parse_carrier(&value)?),
            "state" => filter.state = Some(value.into_owned()),
            _ => {
                return Err(ApiFailure::bad_request(format!(
                    "unknown query field `{}`",
                    name
                )));
            }
        }
    }
    if filter.trace_session_id.is_some() && (seen.contains("cursor") || seen.contains("limit")) {
        return Err(ApiFailure::bad_request(
            "session_ref must not be combined with cursor or limit",
        ));
    }
    validate_filter_strings(
        filter.host.as_deref(),
        filter.user.as_deref(),
        filter.key_id.as_deref(),
        filter.state.as_deref(),
    )?;
    Ok(SessionListRequest {
        limit,
        cursor,
        filter,
    })
}

/// Maps one opaque session-reference failure to the stable API error contract.
pub(super) fn parse_session_ref(
    runtime: &WebProcessRuntime,
    session_ref: &str,
) -> Result<u64, ApiFailure> {
    runtime
        .parse_session_ref(session_ref)
        .map_err(|error| match error {
            SessionRefError::Invalid => ApiFailure::bad_request("Invalid WEB session reference"),
            SessionRefError::StaleInstance => ApiFailure::new(
                StatusCode::CONFLICT,
                "web_runtime_mismatch",
                "WEB session reference belongs to another runtime instance",
            ),
        })
}

fn parse_carrier(value: &str) -> Result<WebCarrier, ApiFailure> {
    WebCarrier::ALL
        .into_iter()
        .find(|carrier| carrier.as_str() == value)
        .ok_or_else(|| {
            ApiFailure::bad_request(
                "carrier must be https, https-lanes, websocket, or websocket-lanes",
            )
        })
}

fn validate_filter_strings(
    host: Option<&str>,
    user: Option<&str>,
    key_id: Option<&str>,
    state: Option<&str>,
) -> Result<(), ApiFailure> {
    if host.is_some_and(|value| value.is_empty() || value.len() > 253) {
        return Err(ApiFailure::bad_request("host must contain 1..253 bytes"));
    }
    if user.is_some_and(|value| value.is_empty() || value.len() > 64) {
        return Err(ApiFailure::bad_request("user must contain 1..64 bytes"));
    }
    if key_id.is_some_and(|value| !lower_hex(value, 16)) {
        return Err(ApiFailure::bad_request(
            "key_id must be 16 lowercase hexadecimal characters",
        ));
    }
    if state.is_some_and(|value| {
        !matches!(
            value,
            "provisional"
                | "replacing"
                | "committed"
                | "healthy"
                | "closing"
                | "superseded"
                | "closed"
        )
    }) {
        return Err(ApiFailure::bad_request("Invalid WEB session state"));
    }
    Ok(())
}

fn parse_user_agent_id(value: &str) -> Result<[u8; 16], ApiFailure> {
    if !lower_hex(value, 32) {
        return Err(ApiFailure::bad_request(
            "user_agent_id must be 32 lowercase hexadecimal characters",
        ));
    }
    let mut id = [0; 16];
    hex::decode_to_slice(value, &mut id).map_err(|_| {
        ApiFailure::bad_request("user_agent_id must be 32 lowercase hexadecimal characters")
    })?;
    Ok(id)
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Returns whether a process instance uses its canonical lowercase form.
pub(super) fn valid_runtime_instance(value: &str) -> bool {
    lower_hex(value, 32)
}

fn parse_canonical_ip(value: &str) -> Result<IpAddr, ApiFailure> {
    let ip = value
        .parse::<IpAddr>()
        .map_err(|_| ApiFailure::bad_request("ip must be a canonical IP address"))?;
    if ip.to_string() != value {
        return Err(ApiFailure::bad_request("ip must use canonical formatting"));
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_identifiers_are_exact_lowercase_hex() {
        assert!(lower_hex("0123456789abcdef", 16));
        assert!(!lower_hex("0123456789ABCDEF", 16));
        assert!(!lower_hex("0123", 16));
        assert!(valid_runtime_instance("0123456789abcdef0123456789abcdef"));
        assert!(!valid_runtime_instance("0123456789ABCDEF0123456789ABCDEF"));
    }

    #[test]
    fn mutation_dtos_reject_unknown_fields() {
        let runtime_instance = "0123456789abcdef0123456789abcdef";
        assert!(
            serde_json::from_value::<RuntimeInstanceRequest>(serde_json::json!({
                "runtime_instance": runtime_instance,
                "extra": true,
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CloseRequest>(serde_json::json!({
                "runtime_instance": runtime_instance,
                "selector": {"kind": "all", "extra": true},
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<DrainRequest>(serde_json::json!({
                "runtime_instance": runtime_instance,
                "timeout_secs": 30,
                "extra": true,
            }))
            .is_err()
        );
    }

    #[test]
    fn filter_ips_require_canonical_text() {
        assert!(parse_canonical_ip("2001:db8::1").is_ok());
        assert!(parse_canonical_ip("2001:0db8::1").is_err());
    }

    #[test]
    fn state_filter_accepts_every_emitted_session_state() {
        for state in [
            "provisional",
            "replacing",
            "committed",
            "healthy",
            "closing",
            "superseded",
            "closed",
        ] {
            assert!(
                validate_filter_strings(None, None, None, Some(state)).is_ok(),
                "state {state} must be accepted"
            );
        }
    }

    #[tokio::test]
    async fn exact_session_query_rejects_pagination_fields_in_any_order() {
        let generation = crate::maestro::generation::test_runtime_generation(
            1,
            crate::config::ProxyConfig::default(),
        );
        let runtime = WebProcessRuntime::start(std::sync::Arc::new(arc_swap::ArcSwap::from(
            generation.clone(),
        )));
        let session_ref = runtime.session_ref(1);
        let cursor = runtime.session_ref(2);

        assert!(
            parse_session_query(
                &runtime,
                Some(&format!("session_ref={session_ref}&cursor={cursor}")),
            )
            .is_err()
        );
        assert!(
            parse_session_query(
                &runtime,
                Some(&format!("limit=2&session_ref={session_ref}")),
            )
            .is_err()
        );

        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}
