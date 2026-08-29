use std::fmt::Write;

use crate::config::{ProxyConfig, WebHttpConnectionCapacityAction};
use crate::web::control::{WebRuntimeLifecycle, WebRuntimePublication};
use crate::web::manager::OperatorLifecycleState;
use crate::web::telemetry::{
    WebDecoyUpstreamOutcome, WebHttpConnectionOverloadOutcome, WebRejectionReason,
};

/// Renders fixed-cardinality process-owned WEB observability families.
pub(super) fn render(out: &mut String, publication: &WebRuntimePublication, config: &ProxyConfig) {
    let runtime = publication.runtime.upgrade();
    let configured_listeners = publication.listeners.len();
    let live_acceptors = publication.telemetry.live_acceptors();
    let accepting_connections = publication.lifecycle == WebRuntimeLifecycle::Running
        && runtime.is_some()
        && configured_listeners != 0
        && live_acceptors == configured_listeners;

    let _ = writeln!(
        out,
        "# HELP telemt_web_ingress_lifecycle_state Current process-owned WEB ingress lifecycle"
    );
    let _ = writeln!(out, "# TYPE telemt_web_ingress_lifecycle_state gauge");
    for state in WebRuntimeLifecycle::ALL {
        let _ = writeln!(
            out,
            "telemt_web_ingress_lifecycle_state{{state=\"{}\"}} {}",
            state.as_str(),
            flag(publication.lifecycle == state)
        );
    }

    let operator_status = runtime
        .as_deref()
        .map(crate::web::manager::WebProcessRuntime::operator_lifecycle_status);
    let _ = writeln!(
        out,
        "# HELP telemt_web_operator_lifecycle_state Current reversible WEB operator lifecycle"
    );
    let _ = writeln!(out, "# TYPE telemt_web_operator_lifecycle_state gauge");
    for state in OPERATOR_STATES {
        let active = match operator_status.as_ref() {
            Some(status) => operator_state_token(status.state) == state,
            None => state == "unavailable",
        };
        let _ = writeln!(
            out,
            "telemt_web_operator_lifecycle_state{{state=\"{state}\"}} {}",
            flag(active)
        );
    }

    let operator_admission_open = operator_status
        .as_ref()
        .is_some_and(|status| status.admission_open);
    let effective_new_work_admission = operator_status
        .as_ref()
        .is_some_and(|status| status.effective_new_work_admission);
    let _ = writeln!(
        out,
        "# HELP telemt_web_ingress_state Independent WEB ingress and admission flags"
    );
    let _ = writeln!(out, "# TYPE telemt_web_ingress_state gauge");
    for (name, value) in [
        ("runtime_available", runtime.is_some()),
        ("accepting_connections", accepting_connections),
        ("config_enabled", config.web.enabled),
        ("operator_admission_open", operator_admission_open),
        ("effective_new_work_admission", effective_new_work_admission),
    ] {
        let _ = writeln!(
            out,
            "telemt_web_ingress_state{{flag=\"{name}\"}} {}",
            flag(value)
        );
    }

    let _ = writeln!(
        out,
        "# HELP telemt_web_listeners Process-owned WEB listener and acceptor counts"
    );
    let _ = writeln!(out, "# TYPE telemt_web_listeners gauge");
    let _ = writeln!(
        out,
        "telemt_web_listeners{{status=\"configured\"}} {configured_listeners}"
    );
    let _ = writeln!(
        out,
        "telemt_web_listeners{{status=\"acceptors_live\"}} {live_acceptors}"
    );

    let _ = writeln!(
        out,
        "# HELP telemt_web_tcp_accept_total Accepted sockets and accept syscall errors"
    );
    let _ = writeln!(out, "# TYPE telemt_web_tcp_accept_total counter");
    let _ = writeln!(
        out,
        "telemt_web_tcp_accept_total{{result=\"accepted\"}} {}",
        publication.telemetry.accepted()
    );
    let _ = writeln!(
        out,
        "telemt_web_tcp_accept_total{{result=\"error\"}} {}",
        publication.telemetry.accept_errors()
    );

    let _ = writeln!(
        out,
        "# HELP telemt_web_rejections_total WEB operational rejection decisions by fixed reason"
    );
    let _ = writeln!(out, "# TYPE telemt_web_rejections_total counter");
    for reason in WebRejectionReason::ALL {
        let _ = writeln!(
            out,
            "telemt_web_rejections_total{{reason=\"{}\"}} {}",
            reason.as_str(),
            publication.telemetry.rejection_total(reason)
        );
    }

    let _ = writeln!(
        out,
        "# HELP telemt_web_http_connection_overload_total Accepted saturated sockets by terminal outcome"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_web_http_connection_overload_total counter"
    );
    for outcome in WebHttpConnectionOverloadOutcome::ALL {
        let _ = writeln!(
            out,
            "telemt_web_http_connection_overload_total{{outcome=\"{}\"}} {}",
            outcome.as_str(),
            publication.telemetry.overload_total(outcome)
        );
    }

    let action = config.web.http_connection_capacity_action;
    let _ = writeln!(
        out,
        "# HELP telemt_web_http_connection_capacity_action Effective overload action"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_web_http_connection_capacity_action gauge"
    );
    for (token, variant) in [
        ("drop", WebHttpConnectionCapacityAction::Drop),
        ("wait", WebHttpConnectionCapacityAction::Wait),
        ("respond", WebHttpConnectionCapacityAction::Respond),
    ] {
        let _ = writeln!(
            out,
            "telemt_web_http_connection_capacity_action{{action=\"{token}\"}} {}",
            flag(action == variant)
        );
    }
    let _ = writeln!(
        out,
        "# HELP telemt_web_http_overload_timeout_milliseconds Effective overload phase timeout"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_web_http_overload_timeout_milliseconds gauge"
    );
    let _ = writeln!(
        out,
        "telemt_web_http_overload_timeout_milliseconds {}",
        config.web.timeouts.http_overload_timeout_ms
    );

    if let Some(runtime) = runtime.as_deref() {
        render_capacity(out, &runtime.capacity_snapshot());
    }

    let _ = writeln!(
        out,
        "# HELP telemt_web_decoy_upstream_requests_total Internal plain-HTTP decoy origin outcomes"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_web_decoy_upstream_requests_total counter"
    );
    for outcome in WebDecoyUpstreamOutcome::ALL {
        let _ = writeln!(
            out,
            "telemt_web_decoy_upstream_requests_total{{outcome=\"{}\"}} {}",
            outcome.as_str(),
            publication.telemetry.decoy_total(outcome)
        );
    }

    render_aggregate_totals(out, publication);
}

fn render_capacity(out: &mut String, snapshot: &crate::web::manager::WebCapacitySnapshot) {
    let _ = writeln!(
        out,
        "# HELP telemt_web_capacity_snapshot_partial Whether a non-blocking capacity plane was omitted"
    );
    let _ = writeln!(out, "# TYPE telemt_web_capacity_snapshot_partial gauge");
    let _ = writeln!(
        out,
        "telemt_web_capacity_snapshot_partial{{plane=\"budget\"}} {}",
        flag(snapshot.partial.contains(&"budget"))
    );
    for (unit, family) in [
        ("slots", "telemt_web_capacity_slots"),
        ("bytes", "telemt_web_capacity_bytes"),
        ("items", "telemt_web_capacity_items"),
    ] {
        let _ = writeln!(
            out,
            "# HELP {family} Current process-wide WEB capacity in {unit}"
        );
        let _ = writeln!(out, "# TYPE {family} gauge");
        for status in snapshot
            .resources
            .iter()
            .filter(|status| status.unit == unit)
        {
            for (kind, value) in [
                ("used", status.used),
                ("available", status.available),
                ("limit", status.limit),
            ] {
                let _ = writeln!(
                    out,
                    "{family}{{resource=\"{}\",kind=\"{kind}\"}} {value}",
                    status.resource
                );
            }
        }
    }
    let _ = writeln!(
        out,
        "# HELP telemt_web_capacity_closed Whether terminal shutdown closed a WEB capacity authority"
    );
    let _ = writeln!(out, "# TYPE telemt_web_capacity_closed gauge");
    let _ = writeln!(
        out,
        "# HELP telemt_web_capacity_saturated Whether a WEB resource has no immediately available capacity"
    );
    let _ = writeln!(out, "# TYPE telemt_web_capacity_saturated gauge");
    for status in &snapshot.resources {
        let _ = writeln!(
            out,
            "telemt_web_capacity_closed{{resource=\"{}\"}} {}",
            status.resource,
            flag(status.closed)
        );
        let _ = writeln!(
            out,
            "telemt_web_capacity_saturated{{resource=\"{}\"}} {}",
            status.resource,
            flag(status.available == 0 && !status.closed)
        );
    }
}

fn render_aggregate_totals(out: &mut String, publication: &WebRuntimePublication) {
    let totals = publication.telemetry.aggregates();
    let _ = writeln!(
        out,
        "# HELP telemt_web_session_incarnations_total Process-owned WEB session lifecycle totals"
    );
    let _ = writeln!(out, "# TYPE telemt_web_session_incarnations_total counter");
    let _ = writeln!(
        out,
        "telemt_web_session_incarnations_total{{event=\"created\"}} {}",
        totals.sessions_created
    );
    let _ = writeln!(
        out,
        "telemt_web_session_incarnations_total{{event=\"closed\"}} {}",
        totals.sessions_closed
    );
    let _ = writeln!(
        out,
        "# HELP telemt_web_streams_total Process-owned WEB logical stream totals"
    );
    let _ = writeln!(out, "# TYPE telemt_web_streams_total counter");
    let _ = writeln!(
        out,
        "telemt_web_streams_total{{event=\"opened\"}} {}",
        totals.streams_opened
    );
    let _ = writeln!(
        out,
        "telemt_web_streams_total{{event=\"rejected\"}} {}",
        totals.streams_rejected
    );
    let _ = writeln!(
        out,
        "# HELP telemt_web_carrier_bytes_total Process-owned WEB carrier payload bytes"
    );
    let _ = writeln!(out, "# TYPE telemt_web_carrier_bytes_total counter");
    let _ = writeln!(
        out,
        "telemt_web_carrier_bytes_total{{direction=\"up\"}} {}",
        totals.bytes_up
    );
    let _ = writeln!(
        out,
        "telemt_web_carrier_bytes_total{{direction=\"down\"}} {}",
        totals.bytes_down
    );
}

fn operator_state_token(state: OperatorLifecycleState) -> &'static str {
    match state {
        OperatorLifecycleState::Running => "running",
        OperatorLifecycleState::Paused => "paused",
        OperatorLifecycleState::Draining => "draining",
        OperatorLifecycleState::ForceClosing => "force_closing",
        OperatorLifecycleState::Drained => "drained",
    }
}

const OPERATOR_STATES: [&str; 6] = [
    "unavailable",
    "running",
    "paused",
    "draining",
    "force_closing",
    "drained",
];

const fn flag(value: bool) -> u8 {
    if value { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use crate::config::ProxyConfig;
    use crate::web::control::WebRuntimeControl;

    #[test]
    fn renderer_emits_complete_zeroed_fixed_counter_sets() {
        let control = WebRuntimeControl::new();
        let publication = control.subscribe().borrow().clone();
        let mut output = String::new();
        super::render(&mut output, &publication, &ProxyConfig::default());

        assert_eq!(
            output.matches("telemt_web_rejections_total{").count(),
            crate::web::telemetry::WebRejectionReason::ALL.len()
        );
        assert_eq!(
            output
                .matches("telemt_web_http_connection_overload_total{")
                .count(),
            crate::web::telemetry::WebHttpConnectionOverloadOutcome::ALL.len()
        );
        assert_eq!(
            output
                .matches("telemt_web_decoy_upstream_requests_total{")
                .count(),
            crate::web::telemetry::WebDecoyUpstreamOutcome::ALL.len()
        );
        assert!(output.contains("telemt_web_ingress_lifecycle_state{state=\"starting\"} 1"));
    }
}
