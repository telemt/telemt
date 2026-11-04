/// Redacts credential-shaped runs in diagnostic text without changing its byte budget.
pub(crate) fn scrub_text(text: &mut String, truncated: bool) {
    let mut bytes = std::mem::take(text).into_bytes();
    scrub_bytes(&mut bytes, truncated);
    // Only ASCII bytes are replaced with ASCII; valid UTF-8 remains valid.
    *text = String::from_utf8(bytes).unwrap_or_default();
}

/// Redacts raw and percent-encoded runs, including prefixes cut by capture limits.
/// This deliberately conservative rule is never used to accept or reject traffic.
pub(super) fn scrub_bytes(bytes: &mut [u8], truncated: bool) {
    let mut start = 0usize;
    let mut count = 0usize;
    let mut offset = 0usize;
    while offset < bytes.len() {
        let (value, consumed) = if bytes[offset] == b'%' && offset + 2 < bytes.len() {
            match (hex(bytes[offset + 1]), hex(bytes[offset + 2])) {
                (Some(a), Some(b)) => ((a << 4) | b, 3),
                _ => (bytes[offset], 1),
            }
        } else {
            (bytes[offset], 1)
        };
        let partial_escape = truncated
            && bytes[offset] == b'%'
            && offset + 2 >= bytes.len()
            && bytes[offset + 1..].iter().all(|byte| hex(*byte).is_some());
        if value.is_ascii_alphanumeric() || matches!(value, b'_' | b'-') || partial_escape {
            if count == 0 {
                start = offset;
            }
            count += 1;
        } else {
            if count >= 43 {
                bytes[start..offset].fill(b'*');
            }
            count = 0;
        }
        offset += consumed;
    }
    if count >= 43 || (truncated && count > 0) {
        bytes[start..].fill(b'*');
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_redaction_handles_raw_encoded_and_every_truncation_boundary() {
        for credential in ["a".repeat(43), "%61".repeat(43)] {
            let complete = format!("prefix/{credential}?ordinary=value");
            let mut text = complete.clone();
            scrub_text(&mut text, false);
            assert_eq!(text.len(), complete.len());
            assert!(text.starts_with("prefix/"));
            assert!(text.ends_with("?ordinary=value"));
            assert!(
                text[7..7 + credential.len()]
                    .bytes()
                    .all(|byte| byte == b'*')
            );
            for end in 1..=credential.len() {
                let mut prefix = format!("prefix/{}", &credential[..end]);
                scrub_text(&mut prefix, true);
                assert!(prefix[7..].bytes().all(|byte| byte == b'*'), "cut {end}");
            }
        }
    }

    #[test]
    fn wildcard_diagnostic_capture_redacts_chunks_and_incomplete_bodies_only_when_enabled() {
        use crate::config::{WebDebugBodyCapture, WebDebugConfig, WebLimitsConfig};
        use crate::web::trace::{TraceBodyState, TraceDirection, TraceRecordKind, WebTraceStore};
        for enabled in [false, true] {
            for end in [
                None,
                Some(TraceBodyState::Aborted),
                Some(TraceBodyState::Error),
                Some(TraceBodyState::Complete),
            ] {
                let policy = WebDebugConfig {
                    enabled: true,
                    body_capture: WebDebugBodyCapture::Full,
                    ..Default::default()
                };
                let store = WebTraceStore::new_with_wildcards(
                    policy.clone(),
                    &WebLimitsConfig {
                        debug_records_capacity: 8,
                        debug_bytes_global: 1 << 20,
                        ..Default::default()
                    },
                    enabled,
                );
                store.apply_policy(2, &policy);
                let request = hyper::Request::builder().uri("/public").body(()).unwrap();
                let trace = store
                    .begin_http(&request, "127.0.0.1".parse().unwrap())
                    .unwrap();
                let bytes = if end == Some(TraceBodyState::Complete) {
                    vec![b'A'; 43]
                } else {
                    vec![b'A'; 21]
                };
                trace.body_data(TraceDirection::Request, &bytes[..10]);
                trace.body_data(TraceDirection::Request, &bytes[10..]);
                if let Some(end) = end {
                    trace.body_finished(TraceDirection::Request, end);
                }
                trace.response_ready(&hyper::Response::new(()));
                trace.body_finished(TraceDirection::Response, TraceBodyState::Complete);
                let records = store.snapshot_matching(|_| true);
                let TraceRecordKind::Http(http) = &records[0].record.kind else {
                    panic!("HTTP record")
                };
                assert_eq!(
                    http.request_body.as_ref().unwrap().captured,
                    if enabled {
                        vec![b'*'; bytes.len()]
                    } else {
                        bytes
                    }
                );
            }
        }
    }
}
