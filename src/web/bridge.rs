use std::sync::OnceLock;

use base64::Engine as _;

use crate::config::WebCarrierMethod;
use crate::crypto::SecureRandom;

/// Browser security policy for the transient Telegram Desktop bridge page.
pub(crate) const PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-create=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), web-share=(), xr-spatial-tracking=()";

/// Fully rendered bridge response and its per-response script policy.
pub(crate) struct BridgePage {
    /// Complete transient HTML document.
    pub(crate) body: String,
    /// Nonce-bound policy that authorizes only the embedded bridge script.
    pub(crate) content_security_policy: String,
}

/// Renders the bounded WEB carrier-negotiation bridge with a fresh CSP nonce.
#[allow(clippy::too_many_arguments)]
pub(crate) fn render(
    host: &str,
    base: &str,
    bootstrap: &str,
    batch_limit: usize,
    queue_limit: usize,
    queue_items: usize,
    max_streams: usize,
    negotiation_enabled: bool,
    candidate_count: usize,
    carrier_deadlines: [u64; 4],
    long_poll_secs: u64,
    bridge_request_secs: u64,
    bridge_retry_secs: u64,
    bridge_recovery_secs: u64,
    websocket_open_secs: u64,
    reconnect_grace_secs: u64,
    carrier_probe_coalesce_ms: u64,
    bridge_diagnostics_enabled: bool,
    carrier_method: WebCarrierMethod,
    retry_jitter: &crate::config::WebRetryJitterConfig,
    rng: &SecureRandom,
) -> BridgePage {
    let mut nonce = [0u8; 18];
    rng.fill(&mut nonce);
    let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
    let base_prefix = base.strip_suffix('/').unwrap_or(base);
    let body = template(bridge_diagnostics_enabled)
        .replace("__NONCE__", &nonce)
        .replace("__HOST__", host)
        .replace("__RETRY_JITTER__", &retry_jitter.bridge_policy())
        .replace("__BASE_PREFIX__", base_prefix)
        .replace("__BOOTSTRAP__", bootstrap)
        .replace("__CARRIER_METHOD__", carrier_method.as_str())
        .replace("__BATCH_LIMIT__", &batch_limit.to_string())
        .replace("__QUEUE_LIMIT__", &queue_limit.to_string())
        .replace("__QUEUE_ITEMS__", &queue_items.to_string())
        .replace("__MAX_STREAMS__", &max_streams.to_string())
        .replace(
            "__NEGOTIATION_ENABLED__",
            if negotiation_enabled { "true" } else { "false" },
        )
        .replace("__CANDIDATE_COUNT__", &candidate_count.to_string())
        .replace("__LONG_POLL_SECS__", &long_poll_secs.to_string())
        .replace("__BRIDGE_REQUEST_SECS__", &bridge_request_secs.to_string())
        .replace("__BRIDGE_RETRY_SECS__", &bridge_retry_secs.to_string())
        .replace(
            "__BRIDGE_RECOVERY_SECS__",
            &bridge_recovery_secs.to_string(),
        )
        .replace("__WEBSOCKET_OPEN_SECS__", &websocket_open_secs.to_string())
        .replace(
            "__RECONNECT_GRACE_SECS__",
            &reconnect_grace_secs.to_string(),
        )
        .replace(
            "__CARRIER_PROBE_COALESCE_MS__",
            &carrier_probe_coalesce_ms.to_string(),
        )
        .replace(
            "__CARRIER_DEADLINES__",
            &carrier_deadlines
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(","),
        );
    BridgePage {
        body,
        content_security_policy: format!(
            "default-src 'none'; base-uri 'none'; child-src 'none'; connect-src 'self' wss://{host}; font-src 'none'; form-action 'none'; frame-ancestors http://127.0.0.1:*; frame-src 'none'; img-src 'none'; manifest-src 'none'; media-src 'none'; object-src 'none'; script-src 'nonce-{nonce}'; style-src 'none'; worker-src 'none'; sandbox allow-same-origin allow-scripts"
        ),
    }
}

// Only immutable embedded source is cached; credentials and CSP nonces stay response-owned.
static TEMPLATES: [OnceLock<String>; 2] = [OnceLock::new(), OnceLock::new()];

/// Prepares both static variants before a WEB runtime accepts requests.
pub(super) fn prepare_templates() {
    template(false);
    template(true);
}

fn template(diagnostics: bool) -> &'static str {
    TEMPLATES[usize::from(diagnostics)].get_or_init(|| assemble_template(diagnostics))
}

fn assemble_template(bridge_diagnostics_enabled: bool) -> String {
    let diagnostic_script = if bridge_diagnostics_enabled {
        format!("<script nonce=\"__NONCE__\">\n{DIAGNOSTIC_RUNTIME}\n</script>\n")
    } else {
        String::new()
    };
    let diagnostic_hook = |method: &str| {
        bridge_diagnostics_enabled
            .then(|| {
                format!("if(clientDiagnostics)try{{clientDiagnostics.{method}()}}catch(error){{}}")
            })
            .unwrap_or_default()
    };
    let diagnostic_runtime_started = if bridge_diagnostics_enabled {
        format!("{}\n", diagnostic_hook("runtimeStarted"))
    } else {
        String::new()
    };
    DOCUMENT
        .replace("__DIAGNOSTIC_RUNTIME__\n", &diagnostic_script)
        .replace("__RESPONSE_RUNTIME__", RESPONSE_RUNTIME)
        .replace("__REQUEST_RUNTIME__", REQUEST_RUNTIME)
        .replace("__BUFFER_RUNTIME__", BUFFER_RUNTIME)
        .replace("__RECOVERY_RUNTIME__", RECOVERY_RUNTIME)
        .replace("__DOWNLINK_RUNTIME__", DOWNLINK_RUNTIME)
        .replace("__CONVEYOR_RUNTIME__", CONVEYOR_RUNTIME)
        .replace("__RUNTIME__", RUNTIME)
        .replace(
            "__DIAGNOSTIC_BINDING__;\n",
            if bridge_diagnostics_enabled {
                "const clientDiagnostics=globalThis.TelemtBridgeDiagnostics;\n"
            } else {
                ""
            },
        )
        .replace(
            "__DIAGNOSTIC_RUNTIME_STARTED__;\n",
            &diagnostic_runtime_started,
        )
        .replace(
            "__DIAGNOSTIC_BOUNDARY_ACTIVATED__;",
            &diagnostic_hook("boundaryActivated"),
        )
        .replace(
            "__STATUS_FUNCTION__",
            if bridge_diagnostics_enabled {
                "state=>{if(port&&!closed){port.postMessage({t:'status',state});if(clientDiagnostics)try{clientDiagnostics.statusPosted()}catch(error){}}}"
            } else {
                "state=>{if(port&&!closed)port.postMessage({t:'status',state})}"
            },
        )
        .replace(
            "__DIAGNOSTIC_HELLO_RECEIVED__;",
            &diagnostic_hook("helloReceived"),
        )
        .replace(
            "__HELLO_TIMEOUT_CALLBACK__",
            if bridge_diagnostics_enabled {
                "()=>{if(clientDiagnostics)try{clientDiagnostics.helloTimeout()}catch(error){}fail('timeout')}"
            } else {
                "()=>fail('timeout')"
            },
        )
        .replace(
            "__DIAGNOSTIC_CLIENT_CLOSE__;",
            &diagnostic_hook("clientCloseBeforeHello"),
        )
        .replace(
            "__PAGEHIDE_CALLBACK__",
            if bridge_diagnostics_enabled {
                "()=>{if(clientDiagnostics)try{clientDiagnostics.documentUnloadedBeforeHello()}catch(error){}fail('navigation')}"
            } else {
                "()=>fail('navigation')"
            },
        )
        .replace(
            "__DIAGNOSTIC_BOOTSTRAP_REPLACED__;",
            if bridge_diagnostics_enabled {
                "if(clientDiagnostics)try{clientDiagnostics.setBootstrap(bootstrap)}catch(error){}"
            } else {
                ""
            },
        )
}

const DOCUMENT: &str = include_str!("bridge/document.html");
const DIAGNOSTIC_RUNTIME: &str = include_str!("bridge/diagnostic.js");
const RESPONSE_RUNTIME: &str = include_str!("bridge/response.js");
const REQUEST_RUNTIME: &str = include_str!("bridge/request.js");
const BUFFER_RUNTIME: &str = include_str!("bridge/buffers.js");
const RECOVERY_RUNTIME: &str = include_str!("bridge/recovery.js");
const DOWNLINK_RUNTIME: &str = include_str!("bridge/downlink.js");
const CONVEYOR_RUNTIME: &str = include_str!("bridge/conveyor.js");
const RUNTIME: &str = include_str!("bridge/runtime.js");

// Rendered wire-contract tests remain separate from the embedded document.
#[cfg(test)]
mod tests;

// Differential tests retain the original renderer as an independent wire-contract oracle.
#[cfg(test)]
#[path = "bridge/render_reference.rs"]
mod render_reference;
#[cfg(test)]
#[path = "bridge/render_tests.rs"]
mod render_tests;
