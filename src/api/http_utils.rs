use http_body_util::{BodyExt, Full};
use hyper::StatusCode;
use hyper::body::{Bytes, Incoming};
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
    hyper::Response::builder()
        .status(status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub(super) fn error_response(request_id: u64, failure: ApiFailure) -> hyper::Response<Full<Bytes>> {
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
            "{{\"ok\":false,\"error\":{{\"code\":\"internal_error\",\"message\":\"serialization failed\"}},\"request_id\":{}}}",
            request_id
        )
        .into_bytes()
    });
    hyper::Response::builder()
        .status(failure.status)
        .header("content-type", "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

pub(super) async fn read_json<T: DeserializeOwned>(
    body: Incoming,
    limit: usize,
) -> Result<T, ApiFailure> {
    let bytes = read_body_with_limit(body, limit).await?;
    serde_json::from_slice(&bytes).map_err(|_| ApiFailure::bad_request("Invalid JSON body"))
}

pub(super) async fn read_optional_json<T: DeserializeOwned>(
    body: Incoming,
    limit: usize,
) -> Result<Option<T>, ApiFailure> {
    let bytes = read_body_with_limit(body, limit).await?;
    if bytes.is_empty() {
        return Ok(None);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| ApiFailure::bad_request("Invalid JSON body"))
}

async fn read_body_with_limit(body: Incoming, limit: usize) -> Result<Vec<u8>, ApiFailure> {
    let mut collected = Vec::new();
    let mut body = body;
    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|_| ApiFailure::bad_request("Invalid request body"))?;
        if let Some(chunk) = frame.data_ref() {
            if collected.len().saturating_add(chunk.len()) > limit {
                return Err(ApiFailure::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "payload_too_large",
                    format!("Body exceeds {} bytes", limit),
                ));
            }
            collected.extend_from_slice(chunk);
        }
    }
    Ok(collected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::StatusCode;
    use serde_json::Value;

    async fn collect_body(resp: hyper::Response<Full<Bytes>>) -> Vec<u8> {
        BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    #[tokio::test]
    async fn success_response_ok_with_object_data() {
        let resp = success_response(
            StatusCode::OK,
            serde_json::json!({"k": "v"}),
            "r1".to_owned(),
        );
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json; charset=utf-8"
        );
        let body: Value = serde_json::from_slice(&collect_body(resp).await).unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["data"]["k"], "v");
        assert_eq!(body["revision"], "r1");
    }

    #[tokio::test]
    async fn success_response_created_with_numeric_data() {
        let resp = success_response(StatusCode::CREATED, 42i32, String::new());
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: Value = serde_json::from_slice(&collect_body(resp).await).unwrap();
        assert_eq!(body["ok"], true);
        assert_eq!(body["data"], 42);
        assert_eq!(body["revision"], "");
    }

    #[tokio::test]
    async fn success_response_null_data() {
        let resp = success_response(StatusCode::OK, Value::Null, "rev".to_owned());
        let body: Value = serde_json::from_slice(&collect_body(resp).await).unwrap();
        assert_eq!(body["ok"], true);
        assert!(body["data"].is_null());
    }

    #[tokio::test]
    async fn error_response_bad_request() {
        let resp = error_response(42, ApiFailure::bad_request("missing"));
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/json; charset=utf-8"
        );
        let body: Value = serde_json::from_slice(&collect_body(resp).await).unwrap();
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "bad_request");
        assert_eq!(body["error"]["message"], "missing");
        assert_eq!(body["request_id"], 42);
    }

    #[tokio::test]
    async fn error_response_internal() {
        let resp = error_response(7, ApiFailure::internal("oops"));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body: Value = serde_json::from_slice(&collect_body(resp).await).unwrap();
        assert_eq!(body["ok"], false);
        assert_eq!(body["error"]["code"], "internal_error");
        assert_eq!(body["request_id"], 7);
    }

    #[tokio::test]
    async fn error_response_not_found() {
        let resp = error_response(
            99,
            ApiFailure::new(StatusCode::NOT_FOUND, "not_found", "no such resource"),
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body: Value = serde_json::from_slice(&collect_body(resp).await).unwrap();
        assert_eq!(body["error"]["code"], "not_found");
        assert_eq!(body["error"]["message"], "no such resource");
    }

    // read_body_with_limit / read_json / read_optional_json require
    // hyper::body::Incoming and are covered by integration tests.
}
