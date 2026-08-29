use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ipnetwork::IpNetwork;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::OwnedSemaphorePermit;
use tokio_util::sync::CancellationToken;

use crate::config::{WebClientIpSource, WebHttpConnectionCapacityAction};
use crate::web::manager::WebProcessRuntime;
use crate::web::telemetry::{WebHttpConnectionOverloadOutcome, WebRejectionReason};

pub(super) const SERVICE_UNAVAILABLE_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nCache-Control: no-store\r\nRetry-After: 1\r\nConnection: close\r\n\r\n";

/// Handles one accepted WEB socket outside ordinary connection capacity.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve(
    stream: TcpStream,
    peer: SocketAddr,
    client_ip_source: WebClientIpSource,
    trusted_proxy_cidrs: Arc<[IpNetwork]>,
    runtime: Arc<WebProcessRuntime>,
    cancellation: CancellationToken,
    overload_permit: OwnedSemaphorePermit,
    action: WebHttpConnectionCapacityAction,
    phase_timeout: Duration,
) {
    match action {
        WebHttpConnectionCapacityAction::Drop => unreachable!("drop is handled before spawn"),
        WebHttpConnectionCapacityAction::Respond => {
            let outcome = respond(stream, &cancellation, phase_timeout).await;
            record_final_capacity_rejection(&runtime, outcome);
            runtime.telemetry().record_overload(outcome);
        }
        WebHttpConnectionCapacityAction::Wait => {
            let connection_permit = tokio::select! {
                biased;
                _ = cancellation.cancelled() => {
                    runtime
                        .telemetry()
                        .record_overload(WebHttpConnectionOverloadOutcome::ShutdownDrop);
                    return;
                }
                permit = tokio::time::timeout(phase_timeout, runtime.acquire_http_connection()) => {
                    permit.ok().flatten()
                }
            };
            let Some(connection_permit) = connection_permit else {
                if runtime.is_shutdown() {
                    runtime
                        .telemetry()
                        .record_overload(WebHttpConnectionOverloadOutcome::ShutdownDrop);
                    return;
                }
                let outcome = match respond(stream, &cancellation, phase_timeout).await {
                    WebHttpConnectionOverloadOutcome::Responded503 => {
                        WebHttpConnectionOverloadOutcome::WaitTimeout503
                    }
                    other => other,
                };
                record_final_capacity_rejection(&runtime, outcome);
                runtime.telemetry().record_overload(outcome);
                return;
            };
            runtime
                .telemetry()
                .record_overload(WebHttpConnectionOverloadOutcome::WaitAdmitted);
            drop(overload_permit);
            crate::web::http::serve_connection(
                stream,
                peer,
                client_ip_source,
                trusted_proxy_cidrs,
                runtime,
                cancellation,
                connection_permit,
            )
            .await;
        }
    }
}

fn record_final_capacity_rejection(
    runtime: &WebProcessRuntime,
    outcome: WebHttpConnectionOverloadOutcome,
) {
    if matches!(
        outcome,
        WebHttpConnectionOverloadOutcome::Responded503
            | WebHttpConnectionOverloadOutcome::WaitTimeout503
            | WebHttpConnectionOverloadOutcome::ResponseErrorDrop
    ) {
        runtime
            .telemetry()
            .record_rejection(WebRejectionReason::HttpConnectionCapacity);
    }
}

async fn respond(
    stream: TcpStream,
    cancellation: &CancellationToken,
    phase_timeout: Duration,
) -> WebHttpConnectionOverloadOutcome {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => WebHttpConnectionOverloadOutcome::ShutdownDrop,
        written = write_service_unavailable(stream, phase_timeout) => {
            if written {
                WebHttpConnectionOverloadOutcome::Responded503
            } else {
                WebHttpConnectionOverloadOutcome::ResponseErrorDrop
            }
        }
    }
}

async fn write_service_unavailable(mut stream: TcpStream, deadline: Duration) -> bool {
    tokio::time::timeout(deadline, async {
        stream.write_all(SERVICE_UNAVAILABLE_RESPONSE).await?;
        stream.shutdown().await
    })
    .await
    .is_ok_and(|result| result.is_ok())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_util::sync::CancellationToken;

    use crate::config::{ProxyConfig, WebClientIpSource, WebHttpConnectionCapacityAction};
    use crate::maestro::generation::test_runtime_generation;
    use crate::web::manager::WebProcessRuntime;
    use crate::web::telemetry::{WebHttpConnectionOverloadOutcome, WebRejectionReason};

    async fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr);
        let server = listener.accept();
        let (client, server) = tokio::join!(client, server);
        (server.unwrap().0, client.unwrap())
    }

    #[tokio::test]
    async fn overload_response_is_exact_retryable_http() {
        let (server, mut client) = tcp_pair().await;
        assert!(super::write_service_unavailable(server, Duration::from_secs(1)).await);

        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, super::SERVICE_UNAVAILABLE_RESPONSE);
    }

    #[tokio::test]
    async fn wait_timeout_is_one_rejection_and_one_retryable_response() {
        let (runtime, generation) = runtime();
        let held = runtime.try_http_connection().unwrap();
        let overload = runtime.try_http_overload_connection().unwrap();
        let (server, mut client) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();

        super::serve(
            server,
            peer,
            WebClientIpSource::XForwardedFor,
            trusted_loopback(),
            Arc::clone(&runtime),
            CancellationToken::new(),
            overload,
            WebHttpConnectionCapacityAction::Wait,
            Duration::from_millis(10),
        )
        .await;
        drop(held);

        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, super::SERVICE_UNAVAILABLE_RESPONSE);
        assert_eq!(
            runtime
                .telemetry()
                .overload_total(WebHttpConnectionOverloadOutcome::WaitTimeout503,),
            1
        );
        assert_eq!(
            runtime
                .telemetry()
                .rejection_total(WebRejectionReason::HttpConnectionCapacity),
            1
        );
        stop(runtime, generation).await;
    }

    #[tokio::test]
    async fn admitted_wait_is_not_counted_as_a_rejection() {
        let (runtime, generation) = runtime();
        let held = runtime.try_http_connection().unwrap();
        let overload = runtime.try_http_overload_connection().unwrap();
        let (server, _client) = tcp_pair().await;
        let peer = server.peer_addr().unwrap();
        let cancellation = CancellationToken::new();
        let task = tokio::spawn(super::serve(
            server,
            peer,
            WebClientIpSource::XForwardedFor,
            trusted_loopback(),
            Arc::clone(&runtime),
            cancellation.clone(),
            overload,
            WebHttpConnectionCapacityAction::Wait,
            Duration::from_secs(1),
        ));
        tokio::task::yield_now().await;
        drop(held);
        for _ in 0..100 {
            if runtime
                .telemetry()
                .overload_total(WebHttpConnectionOverloadOutcome::WaitAdmitted)
                == 1
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            runtime
                .telemetry()
                .overload_total(WebHttpConnectionOverloadOutcome::WaitAdmitted),
            1
        );
        assert_eq!(
            runtime
                .telemetry()
                .rejection_total(WebRejectionReason::HttpConnectionCapacity),
            0
        );
        stop(runtime, generation).await;
    }

    fn runtime() -> (
        Arc<WebProcessRuntime>,
        Arc<crate::maestro::generation::RuntimeGeneration>,
    ) {
        let mut config = ProxyConfig::default();
        config.web.limits.max_http_connections = 1;
        let generation = test_runtime_generation(1, config);
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
        (runtime, generation)
    }

    fn trusted_loopback() -> Arc<[ipnetwork::IpNetwork]> {
        Arc::from(["127.0.0.1/32".parse().unwrap()])
    }

    async fn stop(
        runtime: Arc<WebProcessRuntime>,
        generation: Arc<crate::maestro::generation::RuntimeGeneration>,
    ) {
        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}
