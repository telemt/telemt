use super::*;

pub(super) async fn fetch_via_rustls_stream<S>(
    mut stream: S,
    host: &str,
    sni: &str,
    proxy_header: Option<Vec<u8>>,
    alpn_protocols: &[&[u8]],
) -> Result<TlsFetchResult>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // rustls handshake path for certificate and basic negotiated metadata.
    if let Some(header) = proxy_header.as_ref() {
        stream.write_all(&header).await?;
        stream.flush().await?;
    }

    let config = build_client_config(alpn_protocols);
    let connector = TlsConnector::from(config);

    let server_name = ServerName::try_from(sni.to_owned())
        .or_else(|_| ServerName::try_from(host.to_owned()))
        .map_err(|_| RustlsError::General("invalid SNI".into()))?;

    let tls_stream: TlsStream<S> = connector.connect(server_name, stream).await?;

    // Extract negotiated parameters and certificates
    let (_io, session) = tls_stream.get_ref();
    let cipher_suite = session
        .negotiated_cipher_suite()
        .map(|s| u16::from(s.suite()).to_be_bytes())
        .unwrap_or([0x13, 0x01]);

    let certs: Vec<CertificateDer<'static>> = session
        .peer_certificates()
        .map(|slice| slice.to_vec())
        .unwrap_or_default();
    let cert_chain_der: Vec<Vec<u8>> = certs.iter().map(|c| c.as_ref().to_vec()).collect();
    let cert_payload =
        encode_tls13_certificate_message(&cert_chain_der).map(|certificate_message| {
            TlsCertPayload {
                cert_chain_der: cert_chain_der.clone(),
                certificate_message,
            }
        });

    let total_cert_len = cert_payload
        .as_ref()
        .map(|payload| payload.certificate_message.len())
        .unwrap_or_else(|| cert_chain_der.iter().map(Vec::len).sum::<usize>())
        .max(1024);
    let cert_info = parse_cert_info(&certs);

    // Heuristic: split across two records if large to mimic real servers a bit.
    let app_data_records_sizes = if total_cert_len > 3000 {
        vec![total_cert_len / 2, total_cert_len - total_cert_len / 2]
    } else {
        vec![total_cert_len]
    };

    let parsed = ParsedServerHello {
        version: [0x03, 0x03],
        random: [0u8; 32],
        session_id: Vec::new(),
        cipher_suite,
        compression: 0,
        extensions: Vec::new(),
    };

    debug!(
        sni = %sni,
        len = total_cert_len,
        cipher = format!("0x{:04x}", u16::from_be_bytes(cipher_suite)),
        has_cert_payload = cert_payload.is_some(),
        "Fetched TLS metadata via rustls"
    );

    Ok(TlsFetchResult {
        server_hello_parsed: parsed,
        app_data_records_sizes: app_data_records_sizes.clone(),
        total_app_data_len: app_data_records_sizes.iter().sum(),
        behavior_profile: TlsBehaviorProfile {
            change_cipher_spec_count: 1,
            app_data_record_sizes: app_data_records_sizes,
            ticket_record_sizes: Vec::new(),
            source: TlsProfileSource::Rustls,
            ..TlsBehaviorProfile::default()
        },
        cert_info,
        cert_payload,
    })
}

pub(super) async fn fetch_via_rustls(
    host: &str,
    port: u16,
    sni: &str,
    connect_timeout: Duration,
    upstream: Option<std::sync::Arc<crate::transport::UpstreamManager>>,
    scope: Option<&str>,
    proxy_protocol: u8,
    unix_sock: Option<&str>,
    strict_route: bool,
    alpn_protocols: &[&[u8]],
) -> Result<TlsFetchResult> {
    #[cfg(unix)]
    if let Some(sock_path) = unix_sock {
        match timeout(connect_timeout, UnixStream::connect(sock_path)).await {
            Ok(Ok(stream)) => {
                debug!(
                    sni = %sni,
                    sock = %sock_path,
                    "Rustls fetch using mask unix socket"
                );
                let proxy_header = build_tls_fetch_proxy_header(proxy_protocol, None, None);
                return fetch_via_rustls_stream(stream, host, sni, proxy_header, alpn_protocols)
                    .await;
            }
            Ok(Err(e)) => {
                warn!(
                    sni = %sni,
                    sock = %sock_path,
                    error = %e,
                    "Rustls unix socket connect failed, falling back to TCP"
                );
            }
            Err(_) => {
                warn!(
                    sni = %sni,
                    sock = %sock_path,
                    "Rustls unix socket connect timed out, falling back to TCP"
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
    fetch_via_rustls_stream(stream, host, sni, proxy_header, alpn_protocols).await
}
