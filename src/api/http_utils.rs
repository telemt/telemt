use http_body_util::{BodyExt, Full};
use hyper::StatusCode;
use hyper::body::{Bytes, Incoming};
use hyper::header::{CONTENT_TYPE, HeaderValue};
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::model::{ApiFailure, ErrorBody, ErrorResponse, SuccessResponse};

pub(super) fn success_response<T: Serialize>(
    status: StatusCode,
    data: T,
    revision: String,
) -> hyper::Response<Full<Bytes>> {
    let payload = SuccessResponse {
        ok: true,
        data,
        revision,
    };
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{\"ok\":false}".to_vec());
    build_json_response(status, body)
}

pub(super) fn error_response(
    request_id: u64,
    failure: ApiFailure,
) -> hyper::Response<Full<Bytes>> {
    let payload = ErrorResponse {
        ok: false,
        error: ErrorBody {
            code: failure.code,
            message: failure.message,
        },
        request_id,
    };
    let body = serde_json::to_vec(&payload).unwrap_or_else(|_| {
        format!(
            "{{\"ok\":false,\"error\":{{\"code\":\"internal_error\",\"message\":\"serialization failed\"}},\"request_id\":{request_id}}}"
        )
        .into_bytes()
    });
    build_json_response(failure.status, body)
}

fn build_json_response(status: StatusCode, body: Vec<u8>) -> hyper::Response<Full<Bytes>> {
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| {
            let mut response = hyper::Response::new(Full::new(Bytes::from_static(
                b"{\"ok\":false,\"error\":{\"code\":\"internal_error\",\"message\":\"response_build_failed\"}}",
            )));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response.headers_mut().insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/json; charset=utf-8"),
            );
            response
        })
}

pub(super) async fn read_json<T: DeserializeOwned>(
    body: Incoming,
    limit: usize,
) -> Result<T, ApiFailure> {
    let bytes = read_body_with_limit(body, limit).await?;
    parse_json_bytes(&bytes)
}

pub(super) async fn read_optional_json<T: DeserializeOwned>(
    body: Incoming,
    limit: usize,
) -> Result<Option<T>, ApiFailure> {
    let bytes = read_body_with_limit(body, limit).await?;
    parse_optional_json_bytes(&bytes)
}

async fn read_body_with_limit(body: Incoming, limit: usize) -> Result<Vec<u8>, ApiFailure> {
    let mut collected = Vec::new();
    let mut body = body;
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|_| ApiFailure::bad_request("Invalid request body"))?;
        if let Some(chunk) = frame.data_ref() {
            append_chunk_with_limit(&mut collected, chunk, limit)?;
        }
    }
    Ok(collected)
}

fn append_chunk_with_limit(
    collected: &mut Vec<u8>,
    chunk: &[u8],
    limit: usize,
) -> Result<(), ApiFailure> {
    if collected.len().saturating_add(chunk.len()) > limit {
        return Err(ApiFailure::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            format!("Body exceeds {limit} bytes"),
        ));
    }
    collected.extend_from_slice(chunk);
    Ok(())
}

fn parse_json_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiFailure> {
    serde_json::from_slice(bytes).map_err(|_| ApiFailure::bad_request("Invalid JSON body"))
}

fn parse_optional_json_bytes<T: DeserializeOwned>(bytes: &[u8]) -> Result<Option<T>, ApiFailure> {
    if bytes.is_empty() {
        return Ok(None);
    }
    parse_json_bytes(bytes).map(Some)
}

#[cfg(test)]
mod tests {
    use super::{
        append_chunk_with_limit, error_response, parse_json_bytes, parse_optional_json_bytes,
        success_response,
    };
    use http_body_util::{BodyExt, Full};
    use hyper::StatusCode;
    use hyper::body::Bytes;
    use serde::Deserialize;
    use serde::Serialize;
    use serde_json::Value;

    use crate::api::model::ApiFailure;

    #[derive(Serialize)]
    struct OkPayload {
        value: u32,
    }

    #[derive(Debug, Deserialize)]
    struct ParsedValue {
        value: u32,
    }

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            Err(serde::ser::Error::custom("forced serialization failure"))
        }
    }

    async fn body_to_string(response_body: Full<Bytes>) -> String {
        let collected = match response_body.collect().await {
            Ok(value) => value,
            Err(never) => match never {},
        };
        let bytes = collected.to_bytes();
        String::from_utf8_lossy(bytes.as_ref()).to_string()
    }

    #[tokio::test]
    async fn success_response_serializes_payload_and_revision() {
        let response = success_response(
            StatusCode::OK,
            OkPayload { value: 7 },
            "rev-1".to_string(),
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json; charset=utf-8")
        );

        let body = body_to_string(response.into_body()).await;
        let parsed_opt: Option<Value> = serde_json::from_str(&body).ok();
        assert!(parsed_opt.is_some());
        let parsed = parsed_opt.unwrap_or(Value::Null);

        assert_eq!(parsed.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(parsed.get("revision").and_then(Value::as_str), Some("rev-1"));
        assert_eq!(
            parsed
                .get("data")
                .and_then(|v| v.get("value"))
                .and_then(Value::as_u64),
            Some(7)
        );
    }

    #[tokio::test]
    async fn success_response_falls_back_when_serialization_fails() {
        let response = success_response(StatusCode::ACCEPTED, FailingSerialize, "rev-2".to_string());

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = body_to_string(response.into_body()).await;
        assert_eq!(body, "{\"ok\":false}");
    }

    #[tokio::test]
    async fn error_response_contains_code_message_and_request_id() {
        let response = error_response(
            42,
            ApiFailure::new(StatusCode::BAD_REQUEST, "bad_input", "broken payload"),
        );

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json; charset=utf-8")
        );

        let body = body_to_string(response.into_body()).await;
        let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        assert_eq!(parsed.get("ok").and_then(Value::as_bool), Some(false));
        assert_eq!(
            parsed
                .get("error")
                .and_then(|v| v.get("code"))
                .and_then(Value::as_str),
            Some("bad_input")
        );
        assert_eq!(
            parsed
                .get("error")
                .and_then(|v| v.get("message"))
                .and_then(Value::as_str),
            Some("broken payload")
        );
        assert_eq!(parsed.get("request_id").and_then(Value::as_u64), Some(42));
    }

    #[test]
    fn append_chunk_with_limit_accepts_exact_boundary() {
        let mut out = Vec::new();
        let first = [1u8; 4];
        let second = [2u8; 4];

        assert!(append_chunk_with_limit(&mut out, &first, 8).is_ok());
        assert!(append_chunk_with_limit(&mut out, &second, 8).is_ok());
        assert_eq!(out.len(), 8);
    }

    #[test]
    fn append_chunk_with_limit_rejects_over_boundary() {
        let mut out = Vec::new();
        let first = [1u8; 8];
        let second = [2u8; 1];

        assert!(append_chunk_with_limit(&mut out, &first, 8).is_ok());
        let err = append_chunk_with_limit(&mut out, &second, 8).err();
        assert!(err.is_some());
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing error"));
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(err.code, "payload_too_large");
    }

    #[test]
    fn append_chunk_with_limit_preserves_existing_bytes_on_rejection() {
        let mut out = vec![7u8; 8];
        let rejected = [9u8; 4];

        let err = append_chunk_with_limit(&mut out, &rejected, 8).err();
        assert!(err.is_some());
        assert_eq!(out, vec![7u8; 8]);
    }

    #[test]
    fn parse_json_bytes_rejects_invalid_json() {
        let parsed = parse_json_bytes::<ParsedValue>(b"{not-json}");
        let err = parsed.err();
        assert!(err.is_some());
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing error"));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "bad_request");
    }

    #[test]
    fn parse_json_bytes_rejects_type_confusion() {
        let parsed = parse_json_bytes::<ParsedValue>(b"{\"value\":\"9\"}");
        let err = parsed.err();
        assert!(err.is_some());
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing error"));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "bad_request");
    }

    #[test]
    fn parse_optional_json_bytes_handles_empty_and_valid_payload() {
        let empty = parse_optional_json_bytes::<ParsedValue>(b"");
        assert!(empty.is_ok());
        assert!(empty.ok().flatten().is_none());

        let valid = parse_optional_json_bytes::<ParsedValue>(b"{\"value\":9}");
        assert!(valid.is_ok());
        assert_eq!(valid.ok().flatten().map(|value| value.value), Some(9));
    }

    #[test]
    fn parse_optional_json_bytes_rejects_invalid_payload() {
        let parsed = parse_optional_json_bytes::<ParsedValue>(b"{oops}");
        let err = parsed.err();
        assert!(err.is_some());
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing error"));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "bad_request");
    }

    #[test]
    fn parse_optional_json_bytes_rejects_whitespace_only_payload() {
        let parsed = parse_optional_json_bytes::<ParsedValue>(b" \n\t ");
        let err = parsed.err();
        assert!(err.is_some());
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing error"));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "bad_request");
    }

    #[test]
    fn parse_optional_json_bytes_rejects_trailing_garbage() {
        let parsed = parse_optional_json_bytes::<ParsedValue>(b"{\"value\":9} trailing");
        let err = parsed.err();
        assert!(err.is_some());
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing error"));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.code, "bad_request");
    }

    // ── append_chunk_with_limit boundary cases ────────────────────────────────

    // Adversarial: a single chunk whose length equals the limit exactly must pass.
    // collected.len()(0) + chunk.len()(limit) = limit, NOT > limit → allowed.
    #[test]
    fn append_chunk_with_limit_single_chunk_exactly_at_limit_is_accepted() {
        let mut out = Vec::new();
        let chunk = vec![0xabu8; 256];
        assert!(append_chunk_with_limit(&mut out, &chunk, 256).is_ok());
        assert_eq!(out.len(), 256);
    }

    // Adversarial: a single chunk of limit+1 bytes on an empty buffer must be rejected.
    #[test]
    fn append_chunk_with_limit_single_chunk_one_over_limit_is_rejected() {
        let mut out = Vec::new();
        let chunk = vec![0xabu8; 257];
        let err = append_chunk_with_limit(&mut out, &chunk, 256).err();
        assert!(err.is_some());
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing"));
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
        // Buffer must be unmodified on rejection.
        assert!(out.is_empty());
    }

    // With limit=0, any non-empty chunk must be rejected immediately.
    #[test]
    fn append_chunk_with_limit_zero_limit_rejects_any_nonempty_chunk() {
        let mut out = Vec::new();
        let err = append_chunk_with_limit(&mut out, &[1u8], 0).err();
        assert!(err.is_some());
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing"));
        assert_eq!(err.status, StatusCode::PAYLOAD_TOO_LARGE);
    }

    // With limit=0, an empty chunk (0 bytes) must still pass (0 + 0 not > 0).
    #[test]
    fn append_chunk_with_limit_zero_limit_accepts_empty_chunk() {
        let mut out = Vec::new();
        assert!(append_chunk_with_limit(&mut out, &[], 0).is_ok());
        assert!(out.is_empty());
    }

    // ── parse_json_bytes edge cases ────────────────────────────────────────────

    // Adversarial: empty body must fail, not produce a default-initialised struct.
    #[test]
    fn parse_json_bytes_with_empty_input_fails() {
        let err = parse_json_bytes::<ParsedValue>(b"").err();
        assert!(err.is_some(), "empty body must not silently produce a default value");
        let err = err.unwrap_or_else(|| ApiFailure::bad_request("missing"));
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    // Additional type-confusion: ensure a string value is not coerced to u32.
    #[test]
    fn parse_json_bytes_rejects_numeric_string_for_u32_field() {
        let err = parse_json_bytes::<ParsedValue>(b"{\"value\":\"42\"}").err();
        assert!(err.is_some(), "a JSON string must not be coerced to a u32 field");
    }

    // Adversarial: oversized JSON nested value attempting zip-bomb-style attack
    // cannot bypass the body limit; this test validates that the limit is enforced
    // at collection time, not parsing time.
    #[test]
    fn append_chunk_with_limit_accumulation_check() {
        let mut out = Vec::new();
        // 100 chunks of 10 bytes each = 1000 bytes total, limit = 999.
        for i in 0..99usize {
            append_chunk_with_limit(&mut out, &[0u8; 10], 999)
                .unwrap_or_else(|_| panic!("chunk {i} must be accepted before overflow"));
        }
        // The 100th chunk (10 bytes) pushes total to 1000 > 999 → rejected.
        let err = append_chunk_with_limit(&mut out, &[0u8; 10], 999).err();
        assert!(err.is_some(), "101st byte over the limit must be rejected");
        // Buffer remains at 990 bytes (the 99 accepted chunks).
        assert_eq!(out.len(), 990);
    }
}
