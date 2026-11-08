use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn persisted_source_deny_config() -> ProxyConfig {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("strict.toml");
    std::fs::write(&path,"[general]\nconfig_strict=true\n[general.modes]\nclassic=true\nsecure=true\ntls=true\n[access]\nignore_time_skew=true\n[access.users]\nuser='11111111111111111111111111111111'\n[access.user_source_deny]\nuser=['192.0.2.0/24','2001:db8::/32']\n").unwrap();
    ProxyConfig::load(&path).unwrap()
}

#[tokio::test]
async fn source_deny_mtproto_preserves_authenticated_and_invalid_auth_fallback_paths() {
    let config = persisted_source_deny_config();
    for peer in [
        "192.0.2.1:1234",
        "[2001:db8::1]:1234",
        "198.51.100.1:1234",
        "[2001:db9::1]:1234",
    ] {
        let peer: SocketAddr = peer.parse().unwrap();
        let denied = config.access.is_user_source_ip_denied("user", peer.ip());
        for (secret, valid) in [
            ("11111111111111111111111111111111", true),
            ("22222222222222222222222222222222", false),
        ] {
            for tag in [ProtoTag::Abridged, ProtoTag::Secure] {
                let bytes = make_valid_mtproto_handshake(secret, tag, 2);
                let original = bytes;
                let replay = ReplayChecker::new(64, Duration::from_secs(60));
                let (mut output, writer) = tokio::io::duplex(4096);
                let result = handle_mtproto_handshake(
                    &bytes,
                    &b"tail"[..],
                    writer,
                    peer,
                    &config,
                    &replay,
                    false,
                    None,
                )
                .await;
                if valid && !denied {
                    assert!(
                        matches!(result, HandshakeResult::Success(_)),
                        "{peer}: valid authentication must succeed"
                    );
                } else {
                    let HandshakeResult::BadClient {
                        mut reader,
                        mut writer,
                    } = result
                    else {
                        panic!(
                            "{peer}: denied and invalid authentication must return the fallback streams"
                        );
                    };
                    let mut tail = [0; 4];
                    reader.read_exact(&mut tail).await.unwrap();
                    assert_eq!(&tail, b"tail");
                    writer.write_all(b"fallback").await.unwrap();
                    drop(writer);
                    let mut written = Vec::new();
                    output.read_to_end(&mut written).await.unwrap();
                    assert_eq!(
                        &written, b"fallback",
                        "no protocol response before fallback"
                    );
                }
                assert_eq!(bytes, original);
            }
        }
    }
}

#[tokio::test]
async fn source_deny_tls_preserves_client_hello_and_returns_unmodified_fallback_streams() {
    let config = persisted_source_deny_config();
    for peer in [
        "192.0.2.1:1234",
        "[2001:db8::1]:1234",
        "198.51.100.1:1234",
        "[2001:db9::1]:1234",
    ] {
        let peer: SocketAddr = peer.parse().unwrap();
        let denied = config.access.is_user_source_ip_denied("user", peer.ip());
        for (secret, valid) in [([0x11; 16], true), ([0x22; 16], false)] {
            let bytes = make_valid_tls_handshake(&secret, 0);
            let original = bytes.clone();
            let replay = ReplayChecker::new(64, Duration::from_secs(60));
            let (mut output, writer) = tokio::io::duplex(8192);
            let result = handle_tls_handshake(
                &bytes,
                &b"tail"[..],
                writer,
                peer,
                &config,
                &replay,
                &SecureRandom::new(),
                None,
            )
            .await;
            if valid && !denied {
                assert!(
                    matches!(result, HandshakeResult::Success(_)),
                    "{peer}: valid TLS authentication must succeed"
                );
            } else {
                let HandshakeResult::BadClient {
                    mut reader,
                    mut writer,
                } = result
                else {
                    panic!(
                        "{peer}: denied and invalid TLS authentication must return the fallback streams"
                    );
                };
                let mut tail = [0; 4];
                reader.read_exact(&mut tail).await.unwrap();
                assert_eq!(&tail, b"tail");
                writer.write_all(b"fallback").await.unwrap();
                drop(writer);
                let mut written = Vec::new();
                output.read_to_end(&mut written).await.unwrap();
                assert_eq!(
                    &written, b"fallback",
                    "no ServerHello or alert before fallback"
                );
            }
            assert_eq!(
                bytes, original,
                "the original ClientHello must reach fallback unchanged"
            );
        }
    }
}
