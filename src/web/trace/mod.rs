//! Process-owned bounded WEB request, frame, and lifecycle debug recording.

// HTTP exchange ownership binds byte leases to one request and response.
mod exchange;
// Header, credential, body, and frame sanitization stays independent from storage.
mod sanitize;
// The process-wide store owns policy epochs, ring eviction, and render admission.
mod store;
// Closed record types define the status-page data contract.
mod types;

pub(crate) use exchange::HttpTraceExchange;
pub(crate) use store::{
    StoredTraceRecord, TraceClearOutcome, WebTraceStore, epoch_millis as store_epoch_millis,
};
pub(crate) use types::{
    TraceBodySnapshot, TraceBodyState, TraceDirection, TraceFrame, TraceHeader, TraceIdentity,
    TraceLifecycleContext, TraceLifecycleEvent, TraceLifecycleRecord, TraceRecord, TraceRecordKind,
    TraceRoute, TraceWebSocketContext,
};

// Shape-based sanitization is exclusively for diagnostic copies, never public routing.
mod wildcard;
pub(crate) use wildcard::scrub_text;
