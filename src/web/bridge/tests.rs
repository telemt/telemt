use super::*;

fn has_template_placeholders(page: &BridgePage) -> bool {
    let nonce = page
        .content_security_policy
        .split_once("script-src 'nonce-")
        .expect("rendered page must declare its script nonce")
        .1
        .split_once('\'')
        .expect("script nonce must be terminated")
        .0;
    let attribute = format!("nonce=\"{nonce}\"");
    assert!(
        page.body.contains(&attribute),
        "page must use the policy nonce"
    );
    // URL-safe nonce entropy may contain double underscores without being a template token.
    page.body
        .replace(&attribute, "nonce=\"test\"")
        .contains("__")
}

#[test]
fn placeholder_check_allows_nonce_entropy_but_rejects_unresolved_templates() {
    let mut page = BridgePage {
        body: "<script nonce=\"AA__BBBBBBBBBBBBBBBBBBBB\">resolved</script>".into(),
        content_security_policy: "script-src 'nonce-AA__BBBBBBBBBBBBBBBBBBBB'".into(),
    };
    assert!(!has_template_placeholders(&page));
    page.body.push_str("__RUNTIME__");
    assert!(has_template_placeholders(&page));
}

#[test]
fn carrier_method_is_page_owned_and_used_by_every_https_request() {
    for method in [WebCarrierMethod::Post, WebCarrierMethod::Put] {
        let page = render(
            "proxy.example.com",
            "/telegram/web/",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            2 * 1024 * 1024,
            32 * 1024 * 1024,
            16 * 1024,
            1024,
            true,
            4,
            [3, 5, 8, 12],
            25,
            10,
            90,
            15,
            15,
            120,
            0,
            true,
            method,
            &SecureRandom::new(),
        );
        assert!(!has_template_placeholders(&page));
        assert!(
            page.body
                .contains(&format!("const carrierMethod='{}';", method.as_str()))
        );
        assert_eq!(page.body.matches("carrierMethod=").count(), 1);
        // Execute the rendered POST/PUT page, including retries, instead of counting call sites.
        behavior_tests::run(&page);
        assert_eq!(page.body.matches("options('POST',bootstrap,").count(), 2);
        assert!(
            page.body
                .contains("fetch(relayBase+'/api/v1/diagnostic',{method:'POST'")
        );
        assert!(
            page.body
                .contains("options('DELETE',token,null,headers,undefined,true)")
        );
        assert!(
            page.body
                .contains("method:'GET',signal:requestController.signal")
        );
        assert!(
            page.body
                .contains("exactKeys(value,['v','bootstrap','limits','timeouts','negotiation'])")
        );
        assert!(!page.body.contains("policy.carrier_method"));
        assert!(page.body.contains("port.postMessage({t:'status',state})"));
        assert!(!page.body.contains("port.postMessage({t:'status',state,"));
    }
}

#[path = "behavior_tests.rs"]
mod behavior_tests;

fn render_page(bootstrap: &str, candidate_count: usize) -> BridgePage {
    render(
        "proxy.example.com",
        "/",
        bootstrap,
        2 * 1024 * 1024,
        32 * 1024 * 1024,
        16 * 1024,
        1024,
        true,
        candidate_count,
        [3, 5, 8, 12],
        25,
        10,
        90,
        15,
        15,
        120,
        0,
        false,
        WebCarrierMethod::Post,
        &SecureRandom::new(),
    )
}

fn render_diagnostic_page(bootstrap: &str) -> BridgePage {
    render(
        "proxy.example.com",
        "/",
        bootstrap,
        2 * 1024 * 1024,
        32 * 1024 * 1024,
        16 * 1024,
        1024,
        true,
        4,
        [3, 5, 8, 12],
        25,
        10,
        90,
        15,
        15,
        120,
        0,
        true,
        WebCarrierMethod::Post,
        &SecureRandom::new(),
    )
}

#[test]
fn rendered_page_contains_bounded_negotiation_contract() {
    let page = render_page("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 4);
    assert!(!has_template_placeholders(&page));
    assert!(!page.body.contains("bridge="));
    assert!(page.body.contains("X-Carrier-Capabilities"));
    assert!(page.body.contains("X-Carrier-Attempt"));
    assert!(page.body.contains("candidateCount=4"));
    assert!(page.body.contains("candidateDeadlines=[3,5,8,12]"));
    assert!(page.body.contains("X-Up-Seq"));
    assert!(page.body.contains("X-Lane-ID"));
    assert!(page.body.contains("tproxy-auto-v1."));
    assert!(page.body.contains("tproxy-auto-lane-v1."));
    assert!(page.body.contains("globalThis.TelemtBridgeResponse"));
    assert!(page.body.contains("globalThis.TelemtBridgeRequest"));
    assert!(page.body.contains("globalThis.TelemtBridgeBuffers"));
    assert!(page.body.contains("globalThis.TelemtBridgeRecovery"));
    assert!(page.body.contains("responseBody.read"));
    assert!(!page.body.contains("arrayBuffer()"));
    assert!(page.body.contains("maxChunks=4096"));
    assert!(
        page.content_security_policy
            .contains("frame-ancestors http://127.0.0.1:*")
    );
}

#[test]
fn rendered_page_resolves_carriers_against_the_exact_base_path() {
    let page = render(
        "proxy.example.com",
        "/Dobry-Cola/super_app/",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        2 * 1024 * 1024,
        32 * 1024 * 1024,
        16 * 1024,
        1024,
        true,
        4,
        [3, 5, 8, 12],
        25,
        10,
        90,
        15,
        15,
        120,
        0,
        true,
        WebCarrierMethod::Post,
        &SecureRandom::new(),
    );

    assert!(
        page.body
            .contains("relayBase=relayOrigin+'/Dobry-Cola/super_app'")
    );
    assert!(page.body.contains("fetch(settings.base()+path"));
    assert!(
        page.body
            .contains("relayBase.replace(/^https:/,'wss:')+'/api/v1/ws'")
    );
    assert!(page.body.contains("fetch(relayBase+'/api/v1/diagnostic'"));
    assert!(page.body.contains("url:()=>relayOrigin+recoveryPath"));
    assert!(
        !page
            .body
            .contains("/Dobry-Cola/super_app/Dobry-Cola/super_app")
    );
    assert!(!page.body.contains("__BASE_PREFIX__"));
}

#[test]
fn rendered_page_preserves_the_ios_bootstrap_literal() {
    let bootstrap = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    let page = render_page(bootstrap, 2);
    assert!(
        page.body
            .contains(&format!("let bootstrap=\"{bootstrap}\""))
    );
}

#[test]
fn rendered_page_embeds_the_configured_bridge_timing_policy() {
    let page = render(
        "proxy.example.com",
        "/",
        "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        2 * 1024 * 1024,
        32 * 1024 * 1024,
        16 * 1024,
        1024,
        true,
        4,
        [3, 5, 8, 12],
        17,
        7,
        41,
        13,
        11,
        119,
        4,
        false,
        WebCarrierMethod::Post,
        &SecureRandom::new(),
    );

    assert!(page.body.contains("let longPollMs=17*1000"));
    assert!(page.body.contains("bridgeRequestMs=7*1000"));
    assert!(page.body.contains("bridgeRetryMs=41*1000"));
    assert!(page.body.contains("bridgeRecoveryMs=13*1000"));
    assert!(page.body.contains("websocketOpenMs=11*1000"));
    assert!(page.body.contains("reconnectGraceMs=119*1000"));
    assert!(page.body.contains("let probeCoalesceMs=4"));
    assert!(
        page.body
            .contains("helloTimer=setTimeout(()=>fail('timeout'),bridgeRequestMs)")
    );
    assert!(page.body.contains(
        "if(!createStarted){createStarted=true;if(helloTimer)clearTimeout(helloTimer);helloTimer=null;helloFrame=message.data"
    ));
}

#[test]
fn effective_deadline_formula_uses_the_final_checkpoint() {
    let page = render_page("CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 3);
    assert!(
        page.body
            .contains("negotiatedFinalDeadline=candidateDeadlines[3]")
    );
    assert!(
        page.body
            .contains("carrierAttempt>=negotiatedCandidateCount?negotiatedFinalDeadline")
    );
}

#[test]
fn disabled_negotiation_does_not_arm_a_carrier_deadline() {
    let page = render(
        "proxy.example.com",
        "/",
        "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
        2 * 1024 * 1024,
        32 * 1024 * 1024,
        16 * 1024,
        1024,
        false,
        1,
        [3, 5, 8, 12],
        25,
        10,
        90,
        15,
        15,
        120,
        0,
        false,
        WebCarrierMethod::Post,
        &SecureRandom::new(),
    );
    assert!(page.body.contains(
        "if(negotiationEnabled){negotiationStartedAt=Date.now();armCarrierDeadline(attemptEpoch)}"
    ));
    assert!(
        page.body
            .contains("negotiationEnabled?'tproxy-auto-v1.':'tproxy-v1.'")
    );
}

#[test]
fn retry_and_attempt_state_are_frozen_before_fetch() {
    let page = render_page("EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE", 4);
    assert!(
        page.body.contains(
            "async function send(path,frozenOptions,remainingBudget,maxAttempts,receiver)"
        )
    );
    assert!(!page.body.contains("makeOptions"));
    assert!(page.body.contains(
        "if(settings.closed()||(external&&external.aborted))throw new Error('request aborted')"
    ));
    assert!(page.body.contains(
        "const frozen=options('POST',bootstrap,snapshot.hello,attemptHeaders(snapshot.attempt,snapshot.failure),controller.signal)"
    ));
}

#[test]
fn ambiguous_commit_is_resolved_before_carrier_advance() {
    let page = render_page("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 4);
    assert!(
        page.body
            .contains("if(snapshot.selected){advanceConfirmed(reason,epoch);return}")
    );
    assert!(page.body.contains("resolveAttempt(reason,epoch,snapshot)"));
    assert!(page.body.contains(
        "sessionEcho(response,snapshot.attempt,['provisional','committed','healthy'],true)"
    ));
    assert!(
        page.body
            .contains("if(echo.state!=='provisional'){switching=false;fail('protocol');return}")
    );
    assert!(page.body.contains("const token=cleanupToken||sessionToken"));
    assert!(page.body.contains("'X-Carrier-Failure':terminalFailure"));
    assert!(
        page.body
            .contains("addEventListener('pagehide',()=>fail('navigation')")
    );
}

#[test]
fn rendered_page_preserves_exact_v1_status_control_envelope() {
    let page = render_page("HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH", 4);

    assert_eq!(
        page.body
            .matches("port.postMessage({t:'status',state})")
            .count(),
        1
    );
    assert!(!page.body.contains("port.postMessage({t:'status',state,"));
}

#[test]
fn committed_websocket_lane_escalates_only_pre_upgrade_failure() {
    let page = render_page("LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL", 4);

    assert!(page.body.contains("let upgraded=false,settled=false"));
    assert!(page.body.contains(
        "if(settled)return;settled=true;if(openTimer)clearTimeout(openTimer);openTimer=null"
    ));
    assert!(
        page.body
            .contains("if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened)return")
    );
    assert!(page.body.contains(
        "if(!upgraded){lane.socket=null;opened.close();recoveryController.recover(reason,null);return}"
    ));
    assert!(
        page.body
            .contains("recoveryController.recover(reason,null);return}finishLane(lane,true)")
    );
    assert!(
        page.body
            .contains("openTimer=setTimeout(()=>finishSocket('timeout'),websocketOpenMs)")
    );
    assert!(page.body.contains(
        "if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened){opened.close();return}"
    ));
    assert!(page.body.contains("upgraded=true;lane.ready=true"));
    assert!(page.body.contains(
        "lane.socket.onmessage=event=>{\n  if(openTimer)clearTimeout(openTimer);openTimer=null;\n  if(closed||lanes.get(lane.id)!==lane||lane.socket!==opened||!(event.data instanceof ArrayBuffer))"
    ));
    assert!(
        page.body
            .contains("lane.socket.onclose=()=>finishSocket(upgraded?'network':'upgrade')")
    );
    assert!(page.body.contains("port.postMessage({t:'status',state})"));
    assert!(!page.body.contains("port.postMessage({t:'status',state,"));
}

#[test]
fn bridge_diagnostic_sideband_is_absent_by_default() {
    let page = render_page("IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII", 4);

    assert!(page.body.contains("<body>\n<script nonce=\""));
    assert!(page.body.contains(
        "carrierCapabilities='https,https-lanes,websocket,websocket-lanes';\nconst responseBody="
    ));
    assert!(!page.body.contains("/api/v1/diagnostic"));
    assert!(!page.body.contains("TelemtBridgeDiagnostics"));
    for event in [
        "runtime_started",
        "status_posted",
        "hello_received",
        "boundary_timeout",
        "hello_timeout",
        "client_close_before_hello",
        "document_unloaded_before_hello",
        "runtime_error_before_hello",
    ] {
        assert!(!page.body.contains(event));
    }
}

#[test]
fn enabled_bridge_diagnostics_use_the_https_sideband_only() {
    let page = render_diagnostic_page("JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ");

    assert!(!has_template_placeholders(&page));
    assert!(page.body.contains("fetch(relayBase+'/api/v1/diagnostic'"));
    assert!(page.body.contains("JSON.stringify({v:1,event})"));
    assert!(page.body.contains("'Content-Type':'application/json'"));
    assert!(page.body.contains("keepalive:true"));
    for event in [
        "runtime_started",
        "status_posted",
        "hello_received",
        "boundary_timeout",
        "hello_timeout",
        "client_close_before_hello",
        "document_unloaded_before_hello",
        "runtime_error_before_hello",
    ] {
        assert!(page.body.contains(event));
    }
    assert_eq!(page.body.matches("/api/v1/diagnostic").count(), 1);
}

#[test]
fn bridge_diagnostic_hooks_preserve_native_and_recovery_contracts() {
    let page = render_diagnostic_page("KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK");
    let status_report = page.body.find("clientDiagnostics.statusPosted()").unwrap();
    let native_status = page
        .body
        .find("port.postMessage({t:'status',state})")
        .unwrap();
    let hello_report = page.body.find("clientDiagnostics.helloReceived()").unwrap();
    let create_started = page.body.find("createStarted=true;if(helloTimer)").unwrap();
    let boundary_initialized = page.body.find("initialized=true;port=nextPort;").unwrap();
    let boundary_activated = page
        .body
        .find("clientDiagnostics.boundaryActivated()")
        .unwrap();
    let port_handler = page.body.find("port.onmessage=message=>").unwrap();
    let bootstrap_replaced = page.body.find("bootstrap=policy.bootstrap;").unwrap();
    let diagnostic_rebound = page
        .body
        .find("clientDiagnostics.setBootstrap(bootstrap)")
        .unwrap();
    let limits_replaced = page
        .body
        .find("batchLimit=policy.limits.carrier_batch_bytes")
        .unwrap();

    assert!(native_status < status_report);
    assert!(hello_report < create_started);
    assert!(boundary_initialized < boundary_activated);
    assert!(boundary_activated < port_handler);
    assert!(bootstrap_replaced < diagnostic_rebound);
    assert!(diagnostic_rebound < limits_replaced);
    assert!(page.body.contains("clientDiagnostics.helloTimeout()"));
    assert!(!page.body.contains("port.postMessage({t:'status',state,"));
}
