use super::*;
use crate::crypto::AesCtr;
use crate::maestro::generation::test_runtime_generation;
use crate::protocol::constants::ProtoTag;

#[tokio::test]
async fn strict_me_never_enters_direct_when_pool_or_route_is_missing() {
    for mode in [RelayRouteMode::Direct, RelayRouteMode::Middle] {
        let mut config = ProxyConfig::default();
        config.general.use_middle_proxy = true;
        config.general.me2dc_fallback = false;
        config.upstreams.clear();
        config.access.users.insert("test".into(), "11".repeat(16));
        config.rebuild_runtime_user_auth().unwrap();
        let generation = test_runtime_generation(1, config);
        let mut deps = generation.client_runtime_deps();
        deps.route_runtime = Arc::new(RouteRuntimeController::new(mode));
        let peer = "192.0.2.10:12345".parse().unwrap();
        let success = HandshakeSuccess {
            user: "test".into(),
            dc_idx: 2,
            proto_tag: ProtoTag::Intermediate,
            dec_key: [0; 32],
            dec_iv: 0,
            enc_key: [0; 32],
            enc_iv: 0,
            peer,
            is_tls: false,
        };
        let result = run_authenticated(
            CryptoReader::new(tokio::io::empty(), AesCtr::new(&[0; 32], 0)),
            CryptoWriter::new(tokio::io::sink(), AesCtr::new(&[0; 32], 0), 4096),
            success,
            deps,
            "203.0.113.10:443".parse().unwrap(),
            peer,
            ConntrackClosePolicy::Suppress,
        )
        .await;
        assert!(matches!(
            result,
            Err(ProxyError::Proxy(ref message))
                if message == "Required Middle-End route is unavailable"
        ));
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn direct_remains_available_when_me_is_disabled_or_fallback_is_allowed() {
    for (use_middle_proxy, fallback) in [(false, false), (false, true), (true, true)] {
        for mode in [RelayRouteMode::Direct, RelayRouteMode::Middle] {
            let mut config = ProxyConfig::default();
            config.general.use_middle_proxy = use_middle_proxy;
            config.general.me2dc_fallback = fallback;
            config.upstreams.clear();
            config.access.users.insert("test".into(), "11".repeat(16));
            config.rebuild_runtime_user_auth().unwrap();
            let generation = test_runtime_generation(1, config);
            let mut deps = generation.client_runtime_deps();
            deps.route_runtime = Arc::new(RouteRuntimeController::new(mode));
            let peer = "192.0.2.10:12345".parse().unwrap();
            let success = HandshakeSuccess {
                user: "test".into(),
                dc_idx: 2,
                proto_tag: ProtoTag::Intermediate,
                dec_key: [0; 32],
                dec_iv: 0,
                enc_key: [0; 32],
                enc_iv: 0,
                peer,
                is_tls: false,
            };
            let result = run_authenticated(
                CryptoReader::new(tokio::io::empty(), AesCtr::new(&[0; 32], 0)),
                CryptoWriter::new(tokio::io::sink(), AesCtr::new(&[0; 32], 0), 4096),
                success,
                deps,
                "203.0.113.10:443".parse().unwrap(),
                peer,
                ConntrackClosePolicy::Suppress,
            )
            .await;
            assert!(
                matches!(
                    result,
                    Err(ProxyError::Config(ref message)) if message == "No upstreams available"
                ),
                "direct routing must reach the configured connector: {result:?}"
            );
            generation.stop_sessions().await;
            generation.stop_background_tasks().await;
        }
    }
}
