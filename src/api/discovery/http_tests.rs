use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, watch};

use crate::api::{ApiRuntimeState, ApiShared, events::ApiEventStore, handler};
use crate::config::{ApiGrayAction, ProxyConfig};
use crate::maestro::{
    control_plane::ProcessControlPlane, generation::test_runtime_generation, reload::ReloadControl,
};
use crate::quota_state::QuotaStateOwner;
use crate::stats::QuotaStore;

struct Fixture {
    _directory: tempfile::TempDir,
    shared: Arc<ApiShared>,
}

impl Fixture {
    fn new(whitelist_denied: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("config.toml");
        std::fs::write(&config_path, "# discovery must not edit this source\n").unwrap();
        let mut config = ProxyConfig::default();
        config.server.api.enabled = true;
        config.server.api.read_only = true;
        config.server.api.auth_header = "Bearer discovery-test".into();
        config.server.api.gray_action = ApiGrayAction::Api;
        config.server.api.whitelist = vec![if whitelist_denied {
            "192.0.2.0/24".parse().unwrap()
        } else {
            "127.0.0.1/32".parse().unwrap()
        }];
        let runtime = test_runtime_generation(1, config.clone());
        let shared = ApiShared {
            stats: runtime.stats.clone(),
            ip_tracker: runtime.ip_tracker.clone(),
            me_pool: runtime.me_pool_runtime.clone(),
            upstream_manager: runtime.upstream_manager.clone(),
            config_path,
            quota_state: QuotaStateOwner::new(
                directory.path().join("quota.json"),
                Arc::new(QuotaStore::default()),
            ),
            detected_ips_rx: watch::channel((None, None)).1,
            mutation_lock: Arc::new(Mutex::new(())),
            minimal_cache: Arc::new(Mutex::new(None)),
            runtime_edge_connections_cache: Arc::new(Mutex::new(None)),
            runtime_edge_recompute_lock: Arc::new(Mutex::new(())),
            cache_generation: Arc::new(AtomicU64::new(1)),
            runtime_events: Arc::new(ApiEventStore::new(64)),
            request_id: Arc::new(AtomicU64::new(1)),
            runtime_state: Arc::new(ApiRuntimeState {
                process_started_at_epoch_secs: 0,
                config_reload_count: AtomicU64::new(0),
                last_config_reload_epoch_secs: AtomicU64::new(0),
                admission_open: AtomicBool::new(true),
            }),
            startup_tracker: Arc::new(crate::startup::StartupTracker::new(0)),
            route_runtime: runtime.route_runtime.clone(),
            proxy_shared: runtime.proxy_shared.clone(),
            reload_control: ReloadControl::channel(1).0,
            active_runtime: Arc::new(arc_swap::ArcSwap::from(runtime)),
            web_trace: crate::web::trace::WebTraceStore::new(config.web.debug, &config.web.limits),
            web_runtime_rx: crate::web::control::WebRuntimeControl::new().subscribe(),
            control_plane: ProcessControlPlane::new(),
        };
        Self {
            _directory: directory,
            shared: Arc::new(shared),
        }
    }

    async fn request(&self, method: &str, path: &str, authorized: bool) -> (u16, String, Value) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let shared = self.shared.clone();
        let server = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    service_fn(move |request| handler::handle(request, peer, shared.clone())),
                )
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let mut request = client
            .request(method.parse().unwrap(), format!("http://{address}{path}"))
            .header("Connection", "close");
        if authorized {
            request = request.header("Authorization", "Bearer discovery-test");
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let allow = response
            .headers()
            .get("allow")
            .map(|value| value.to_str().unwrap().to_owned())
            .unwrap_or_default();
        let body = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        (status, allow, body)
    }
}

#[tokio::test]
async fn discovery_http_preserves_auth_read_only_and_method_contracts() {
    let fixture = Fixture::new(false);
    let original = std::fs::read(&fixture.shared.config_path).unwrap();
    for path in ["/v1/capabilities", "/v1/config/schema"] {
        let (status, _, body) = fixture.request("GET", path, false).await;
        assert_eq!(status, 401);
        assert_eq!(body["error"]["code"], "unauthorized");

        let (status, _, body) = fixture.request("GET", path, true).await;
        assert_eq!(status, 200);
        assert_eq!(body["ok"], true);
        assert_eq!(body["data"]["schema_version"], 1);
        assert!(
            body["revision"]
                .as_str()
                .is_some_and(|value| !value.is_empty())
        );

        let (status, allow, body) = fixture.request("POST", path, true).await;
        assert_eq!(status, 405);
        assert_eq!(allow, "GET");
        assert_eq!(body["error"]["code"], "method_not_allowed");

        let (status, _, body) = fixture
            .request("GET", &format!("{path}?extra=1"), true)
            .await;
        assert_eq!(status, 400);
        assert_eq!(body["error"]["code"], "bad_request");
    }
    assert_eq!(
        std::fs::read(&fixture.shared.config_path).unwrap(),
        original
    );
}

#[tokio::test]
async fn discovery_http_preserves_whitelist_gate() {
    let fixture = Fixture::new(true);
    for path in ["/v1/capabilities", "/v1/config/schema"] {
        let (status, _, body) = fixture.request("GET", path, true).await;
        assert_eq!(status, 403);
        assert_eq!(body["error"]["code"], "forbidden");
    }
}

#[tokio::test]
async fn capabilities_http_does_not_wait_for_contended_me_pool() {
    let fixture = Fixture::new(false);
    // Keep the writer alive until after the HTTP response: a blocking sample
    // would time out instead of describing the unknown prerequisite.
    let _guard = fixture.shared.me_pool.write().await;
    let (status, _, body) = fixture.request("GET", "/v1/capabilities", true).await;
    assert_eq!(status, 200);
    let operation = body["data"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|operation| operation["id"] == "runtime_me_pool_state")
        .unwrap();
    assert!(operation["available"].is_null());
    assert_eq!(operation["unavailable_reason"], "snapshot_busy");
}
