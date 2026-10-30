use super::*;
use crate::web::trace::{TraceBodyState, TraceRecordKind};

#[tokio::test]
async fn wildcard_unknown_foreign_credentials_preserve_decoy_bytes_but_not_diagnostic_copies() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let text = wildcard_source(
        "hosts = [\"*.example.com\", \"exact.example.com\"]",
        site.local_addr().unwrap(),
    ) + "\n[web.debug]\nenabled = true\nbody_capture = \"full\"\ncapture_headers = true\n";
    let generation = generation(1, &text);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation.clone())));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let foreign = capability(&generation.config(), "unseen.example.com");
    let encoded = foreign
        .bytes()
        .map(|byte| format!("%{byte:02X}"))
        .collect::<String>();
    let echoed = format!("response/{encoded}/end");
    let expected = echoed.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = site.accept().await.unwrap();
        let mut received = Vec::new();
        let mut byte = [0; 1];
        while !received.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.unwrap();
            received.push(byte[0]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: {}\r\nConnection: close\r\n\r\n{}",
            echoed.len(),
            echoed,
            echoed
        );
        stream.write_all(response.as_bytes()).await.unwrap();
        received
    });
    let response = request(
        &listener,
        &runtime,
        raw_request(
            "GET",
            &format!("/public/{encoded}"),
            "exact.example.com",
            &format!(
                "Cookie: ordinary={foreign}\r\nUser-Agent: {foreign}\r\nX-{foreign}: ordinary\r\n"
            ),
            &[],
        ),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(split_response(&response).1, expected.as_bytes());
    assert_eq!(
        response_header(split_response(&response).0, "etag"),
        expected
    );
    let forwarded = String::from_utf8(server.await.unwrap()).unwrap();
    assert!(forwarded.contains(&encoded));
    assert!(forwarded.contains(&foreign));
    let records = runtime
        .trace()
        .snapshot_matching(|record| matches!(record.kind, TraceRecordKind::Http(_)));
    assert_eq!(records.len(), 1);
    let record = &records[0].record;
    assert!(!record.user_agent.as_ref().unwrap().contains(&foreign));
    let TraceRecordKind::Http(http) = &record.kind else {
        panic!("HTTP trace")
    };
    assert!(!http.path.contains(&encoded));
    assert!(http.request_headers.iter().all(|header| {
        !header.name.contains(&foreign.to_ascii_lowercase())
            && !header
                .value
                .as_ref()
                .is_some_and(|value| value.contains(&foreign))
    }));
    assert!(http.response_headers.iter().all(|header| {
        !header
            .value
            .as_ref()
            .is_some_and(|value| value.contains(&encoded))
    }));
    let body = http.response_body.as_ref().unwrap();
    assert_eq!(body.state, TraceBodyState::Complete);
    assert!(!String::from_utf8_lossy(&body.captured).contains(&encoded));
    assert_eq!(runtime.wildcard.as_ref().unwrap().test_stats(), (0, 0, 0));
    drop(records);
    stop(runtime, &[generation]).await;
}
