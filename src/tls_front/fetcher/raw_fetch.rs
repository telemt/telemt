use super::*;

pub(super) fn encode_tls13_certificate_message(cert_chain_der: &[Vec<u8>]) -> Option<Vec<u8>> {
    if cert_chain_der.is_empty() {
        return None;
    }

    let mut certificate_list = Vec::new();
    for cert in cert_chain_der {
        if cert.is_empty() {
            return None;
        }
        certificate_list.extend_from_slice(&u24_bytes(cert.len())?);
        certificate_list.extend_from_slice(cert);
        certificate_list.extend_from_slice(&0u16.to_be_bytes()); // cert_entry extensions
    }

    // Certificate = context_len(1) + certificate_list_len(3) + entries
    let body_len = 1usize.checked_add(3)?.checked_add(certificate_list.len())?;

    let mut message = Vec::with_capacity(4 + body_len);
    message.push(0x0b); // HandshakeType::certificate
    message.extend_from_slice(&u24_bytes(body_len)?);
    message.push(0x00); // certificate_request_context length
    message.extend_from_slice(&u24_bytes(certificate_list.len())?);
    message.extend_from_slice(&certificate_list);
    Some(message)
}

pub(super) async fn fetch_via_raw_tls_stream<S>(
    mut stream: S,
    sni: &str,
    connect_timeout: Duration,
    proxy_header: Option<Vec<u8>>,
    profile: TlsFetchProfile,
    grease_enabled: bool,
    deterministic: bool,
) -> Result<TlsFetchResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let rng = SecureRandom::new();
    let client_hello = build_client_hello(sni, &rng, profile, grease_enabled, deterministic);
    timeout(connect_timeout, async {
        if let Some(header) = proxy_header.as_ref() {
            stream.write_all(&header).await?;
        }
        stream.write_all(&client_hello).await?;
        stream.flush().await?;
        Ok::<(), std::io::Error>(())
    })
    .await??;

    let mut records = Vec::new();
    let mut app_records_seen = 0usize;
    // Read a bounded encrypted flight: ServerHello, CCS, certificate-like data,
    // and a small number of ticket-like tail records.
    for _ in 0..8 {
        match timeout(connect_timeout, read_tls_record(&mut stream)).await {
            Ok(Ok(rec)) => {
                if rec.0 == TLS_RECORD_APPLICATION {
                    app_records_seen += 1;
                }
                records.push(rec);
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => break,
        }
        if app_records_seen >= 4 {
            break;
        }
    }

    let mut server_hello = None;
    let mut server_hello_record_len = 0usize;
    for (t, body) in &records {
        if *t == TLS_RECORD_HANDSHAKE && server_hello.is_none() {
            server_hello = parse_server_hello(body);
            server_hello_record_len = body.len();
        }
    }

    let parsed = server_hello.ok_or_else(|| anyhow!("ServerHello not received"))?;
    let mut behavior_profile = derive_behavior_profile(&records);
    behavior_profile.server_hello_record_len = server_hello_record_len;
    behavior_profile.refresh_server_hello_summary(&parsed);
    let mut app_sizes = behavior_profile.app_data_record_sizes.clone();
    app_sizes.extend_from_slice(&behavior_profile.ticket_record_sizes);
    let total_app_data_len = app_sizes.iter().sum::<usize>().max(1024);
    let app_data_records_sizes = if app_sizes.is_empty() {
        vec![total_app_data_len]
    } else {
        app_sizes
    };

    Ok(TlsFetchResult {
        server_hello_parsed: parsed,
        app_data_records_sizes,
        total_app_data_len,
        behavior_profile,
        cert_info: None,
        cert_payload: None,
    })
}

pub(super) async fn fetch_via_raw_tls(
    host: &str,
    port: u16,
    sni: &str,
    connect_timeout: Duration,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    proxy_protocol: u8,
    unix_sock: Option<&str>,
    strict_route: bool,
    profile: TlsFetchProfile,
    grease_enabled: bool,
    deterministic: bool,
) -> Result<TlsFetchResult> {
    #[cfg(unix)]
    if let Some(sock_path) = unix_sock {
        match timeout(connect_timeout, UnixStream::connect(sock_path)).await {
            Ok(Ok(stream)) => {
                debug!(
                    sni = %sni,
                    sock = %sock_path,
                    "Raw TLS fetch using mask unix socket"
                );
                let proxy_header = build_tls_fetch_proxy_header(proxy_protocol, None, None);
                return fetch_via_raw_tls_stream(
                    stream,
                    sni,
                    connect_timeout,
                    proxy_header,
                    profile,
                    grease_enabled,
                    deterministic,
                )
                .await;
            }
            Ok(Err(e)) => {
                warn!(
                    sni = %sni,
                    sock = %sock_path,
                    error = %e,
                    "Raw TLS unix socket connect failed, falling back to TCP"
                );
            }
            Err(_) => {
                warn!(
                    sni = %sni,
                    sock = %sock_path,
                    "Raw TLS unix socket connect timed out, falling back to TCP"
                );
            }
        }
    }

    #[cfg(not(unix))]
    let _ = unix_sock;

    let stream =
        connect_tcp_with_upstream(host, port, connect_timeout, upstream, scope, strict_route)
            .await?;
    let (src_addr, dst_addr) = socket_addrs_from_upstream_stream(&stream);
    let proxy_header = build_tls_fetch_proxy_header(proxy_protocol, src_addr, dst_addr);
    fetch_via_raw_tls_stream(
        stream,
        sni,
        connect_timeout,
        proxy_header,
        profile,
        grease_enabled,
        deterministic,
    )
    .await
}
