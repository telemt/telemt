use super::*;
use std::collections::HashSet;
use std::sync::{Arc, Barrier};

#[path = "render_benchmarks.rs"]
mod benchmarks;

#[test]
fn disabled_runtime_prewarms_templates_before_hot_enable() {
    const CHILD: &str = "TELEMT_TEST_BRIDGE_PREWARM_CHILD";
    if std::env::var_os(CHILD).is_none() {
        // A fresh process prevents unrelated render tests from satisfying the warmup assertion.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "web::bridge::render_tests::disabled_runtime_prewarms_templates_before_hot_enable",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed; 0 failed"),
            "{}\n{}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    assert!(TEMPLATES.iter().all(|template| template.get().is_none()));
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut config = crate::config::ProxyConfig::default();
            config.web.enabled = false;
            let generation = crate::maestro::generation::test_runtime_generation(1, config);
            let runtime = crate::web::manager::WebProcessRuntime::start(Arc::new(
                arc_swap::ArcSwap::from(Arc::clone(&generation)),
            ));
            assert!(TEMPLATES.iter().all(|template| template.get().is_some()));
            runtime.shutdown().await;
            generation.stop_sessions().await;
            generation.stop_background_tasks().await;
        });
}

struct Case {
    host: String,
    base: String,
    bootstrap: String,
    diagnostics: bool,
    method: WebCarrierMethod,
    negotiation: bool,
    candidates: usize,
    value: usize,
    jitter: crate::config::WebRetryJitterConfig,
}

impl Case {
    fn new(index: usize) -> Self {
        Self {
            jitter: crate::config::WebRetryJitterConfig::default(),
            host: format!("proxy-{index}.example.com"),
            base: "/telegram/web/".to_string(),
            bootstrap: format!("{index:043}"),
            diagnostics: index % 2 != 0,
            method: if index % 3 == 0 {
                WebCarrierMethod::Put
            } else {
                WebCarrierMethod::Post
            },
            negotiation: index % 2 == 0,
            candidates: index % 4 + 1,
            value: index + 1,
        }
    }

    fn render(&self, rng: &SecureRandom) -> BridgePage {
        render(
            &self.host,
            &self.base,
            &self.bootstrap,
            self.value * 1024,
            self.value * 4096,
            self.value * 4,
            self.value,
            self.negotiation,
            self.candidates,
            [3, 5, 8, 12],
            self.value as u64,
            self.value as u64 + 1,
            self.value as u64 + 2,
            self.value as u64 + 3,
            self.value as u64 + 4,
            self.value as u64 + 5,
            self.value as u64 - 1,
            self.diagnostics,
            self.method,
            &self.jitter,
            rng,
        )
    }

    fn reference(&self, nonce: &str) -> BridgePage {
        render_reference::render(
            &self.host,
            &self.base,
            &self.bootstrap,
            self.value * 1024,
            self.value * 4096,
            self.value * 4,
            self.value,
            self.negotiation,
            self.candidates,
            [3, 5, 8, 12],
            self.value as u64,
            self.value as u64 + 1,
            self.value as u64 + 2,
            self.value as u64 + 3,
            self.value as u64 + 4,
            self.value as u64 + 5,
            self.value as u64 - 1,
            self.diagnostics,
            self.method,
            &self.jitter,
            nonce,
        )
    }

    fn assert_page(&self, page: &BridgePage) -> String {
        let nonce = page
            .content_security_policy
            .split_once("script-src 'nonce-")
            .unwrap()
            .1
            .split_once('\'')
            .unwrap()
            .0;
        assert_eq!(nonce.len(), 24);
        let expected = self.reference(nonce);
        assert_eq!(page.body, expected.body);
        assert_eq!(
            page.content_security_policy,
            expected.content_security_policy
        );
        assert_eq!(
            page.body.matches(&format!("nonce=\"{nonce}\"")).count(),
            if self.diagnostics { 8 } else { 7 }
        );
        nonce.to_string()
    }
}

#[test]
fn cached_templates_preserve_exact_dynamic_substitution_order() {
    prepare_templates();
    let rng = SecureRandom::new();
    let long_base = format!("/{}/", "a".repeat(126));
    let bases = [
        "/",
        "/telegram/web/",
        "/a__BOOTSTRAP__/",
        "/a__CARRIER_DEADLINES__/",
        long_base.as_str(),
    ];
    for diagnostics in [false, true] {
        for method in [WebCarrierMethod::Post, WebCarrierMethod::Put] {
            for negotiation in [false, true] {
                for candidates in 1..=4 {
                    for base in bases {
                        let mut case = Case::new(candidates);
                        case.diagnostics = diagnostics;
                        case.method = method;
                        case.negotiation = negotiation;
                        case.candidates = candidates;
                        case.base = base.to_string();
                        case.assert_page(&case.render(&rng));
                    }
                }
            }
        }
    }
}

#[test]
fn concurrent_responses_keep_nonces_and_configuration_response_owned() {
    prepare_templates();
    let pointers = [
        template(false).as_ptr() as usize,
        template(true).as_ptr() as usize,
    ];
    let barrier = Arc::new(Barrier::new(32));
    let nonces = std::thread::scope(|scope| {
        let handles = (0..32)
            .map(|worker| {
                let barrier = Arc::clone(&barrier);
                scope.spawn(move || {
                    let rng = SecureRandom::new();
                    barrier.wait();
                    (0..8)
                        .map(|iteration| {
                            let case = Case::new(worker * 8 + iteration);
                            case.assert_page(&case.render(&rng))
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(nonces.iter().collect::<HashSet<_>>().len(), nonces.len());
    assert_eq!(
        pointers,
        [
            template(false).as_ptr() as usize,
            template(true).as_ptr() as usize
        ]
    );
    for diagnostics in [false, true] {
        assert!(template(diagnostics).contains("__NONCE__"));
        assert!(template(diagnostics).contains("__BOOTSTRAP__"));
        assert!(template(diagnostics).contains("__BASE_PREFIX__"));
    }
}

#[test]
fn retry_jitter_is_rendered_per_page_without_changing_existing_pages() {
    let rng = SecureRandom::new();
    let mut case = Case::new(1);
    let old = case.render(&rng);
    case.jitter.enabled = true;
    case.jitter.min_ms = 10;
    case.jitter.max_ms = 301;
    case.jitter.distribution = crate::config::WebRetryJitterDistribution::Triangular;
    let new = case.render(&rng);
    assert!(
        old.body
            .contains("{enabled:false,min:0,max:250,peak:125,triangular:false}")
    );
    assert!(
        new.body
            .contains("{enabled:true,min:10,max:301,peak:155.5,triangular:true}")
    );
    let nonce = case.assert_page(&new);
    assert_eq!(new.body, case.reference(&nonce).body);
}
