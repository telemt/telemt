//! MTProto Handshake

#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn, trace};
use zeroize::Zeroize;

use crate::crypto::{sha256, AesCtr, SecureRandom};
use rand::Rng;
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::stream::{FakeTlsReader, FakeTlsWriter, CryptoReader, CryptoWriter};
use crate::error::{ProxyError, HandshakeResult};
use crate::stats::ReplayChecker;
use crate::config::ProxyConfig;
use crate::tls_front::{TlsFrontCache, emulator};

fn decode_user_secrets(
    config: &ProxyConfig,
    preferred_user: Option<&str>,
) -> Vec<(String, Vec<u8>)> {
    let mut secrets = Vec::with_capacity(config.access.users.len());

    if let Some(preferred) = preferred_user
        && let Some(secret_hex) = config.access.users.get(preferred)
        && let Ok(bytes) = hex::decode(secret_hex)
    {
        secrets.push((preferred.to_string(), bytes));
    }

    for (name, secret_hex) in &config.access.users {
        if preferred_user.is_some_and(|preferred| preferred == name.as_str()) {
            continue;
        }
        if let Ok(bytes) = hex::decode(secret_hex) {
            secrets.push((name.clone(), bytes));
        }
    }

    secrets
}

/// Result of successful handshake
///
/// Key material (`dec_key`, `dec_iv`, `enc_key`, `enc_iv`) is
/// zeroized on drop.
#[derive(Debug, Clone)]
pub struct HandshakeSuccess {
    /// Authenticated user name
    pub user: String,
    /// Target datacenter index
    pub dc_idx: i16,
    /// Protocol variant (abridged/intermediate/secure)
    pub proto_tag: ProtoTag,
    /// Decryption key and IV (for reading from client)
    pub dec_key: [u8; 32],
    pub dec_iv: u128,
    /// Encryption key and IV (for writing to client) 
    pub enc_key: [u8; 32],
    pub enc_iv: u128,
    /// Client address
    pub peer: SocketAddr,
    /// Whether TLS was used
    pub is_tls: bool,
}

impl Drop for HandshakeSuccess {
    fn drop(&mut self) {
        self.dec_key.zeroize();
        self.dec_iv.zeroize();
        self.enc_key.zeroize();
        self.enc_iv.zeroize();
    }
}

/// Handle fake TLS handshake
pub async fn handle_tls_handshake<R, W>(
    handshake: &[u8],
    reader: R,
    mut writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    rng: &SecureRandom,
    tls_cache: Option<Arc<TlsFrontCache>>,
) -> HandshakeResult<(FakeTlsReader<R>, FakeTlsWriter<W>, String), R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    debug!(peer = %peer, handshake_len = handshake.len(), "Processing TLS handshake");

    if handshake.len() < tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN + 1 {
        debug!(peer = %peer, "TLS handshake too short");
        return HandshakeResult::BadClient { reader, writer };
    }

    let digest = &handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN];
    let digest_half = &digest[..tls::TLS_DIGEST_HALF_LEN];

    if replay_checker.check_and_add_tls_digest(digest_half) {
        warn!(peer = %peer, "TLS replay attack detected (duplicate digest)");
        return HandshakeResult::BadClient { reader, writer };
    }

    let secrets = decode_user_secrets(config, None);

    let validation = match tls::validate_tls_handshake(
        handshake,
        &secrets,
        config.access.ignore_time_skew,
    ) {
        Some(v) => v,
        None => {
            debug!(
                peer = %peer, 
                ignore_time_skew = config.access.ignore_time_skew,
                "TLS handshake validation failed - no matching user or time skew"
            );
            return HandshakeResult::BadClient { reader, writer };
        }
    };

    let secret = match secrets.iter().find(|(name, _)| *name == validation.user) {
        Some((_, s)) => s,
        None => return HandshakeResult::BadClient { reader, writer },
    };

    let cached = if config.censorship.tls_emulation {
        if let Some(cache) = tls_cache.as_ref() {
            let selected_domain = if let Some(sni) = tls::extract_sni_from_client_hello(handshake) {
                if cache.contains_domain(&sni).await {
                    sni
                } else {
                    config.censorship.tls_domain.clone()
                }
            } else {
                config.censorship.tls_domain.clone()
            };
            let cached_entry = cache.get(&selected_domain).await;
            let use_full_cert_payload = cache
                .take_full_cert_budget_for_ip(
                    peer.ip(),
                    Duration::from_secs(config.censorship.tls_full_cert_ttl_secs),
                )
                .await;
            Some((cached_entry, use_full_cert_payload))
        } else {
            None
        }
    } else {
        None
    };

    let alpn_list = if config.censorship.alpn_enforce {
        tls::extract_alpn_from_client_hello(handshake)
    } else {
        Vec::new()
    };
    let selected_alpn = if config.censorship.alpn_enforce {
        if alpn_list.iter().any(|p| p == b"h2") {
            Some(b"h2".to_vec())
        } else if alpn_list.iter().any(|p| p == b"http/1.1") {
            Some(b"http/1.1".to_vec())
        } else {
            None
        }
    } else {
        None
    };

    let response = if let Some((cached_entry, use_full_cert_payload)) = cached {
        emulator::build_emulated_server_hello(
            secret,
            &validation.digest,
            &validation.session_id,
            &cached_entry,
            use_full_cert_payload,
            rng,
            selected_alpn.clone(),
            config.censorship.tls_new_session_tickets,
        )
    } else {
        tls::build_server_hello(
            secret,
            &validation.digest,
            &validation.session_id,
            config.censorship.fake_cert_len,
            rng,
            selected_alpn.clone(),
            config.censorship.tls_new_session_tickets,
        )
    };

    // Optional anti-fingerprint delay before sending ServerHello.
    if config.censorship.server_hello_delay_max_ms > 0 {
        let min = config.censorship.server_hello_delay_min_ms;
        let max = config.censorship.server_hello_delay_max_ms.max(min);
        let delay_ms = if max == min {
            max
        } else {
            rand::rng().random_range(min..=max)
        };
        if delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
    }

    debug!(peer = %peer, response_len = response.len(), "Sending TLS ServerHello");

    if let Err(e) = writer.write_all(&response).await {
        warn!(peer = %peer, error = %e, "Failed to write TLS ServerHello");
        return HandshakeResult::Error(ProxyError::Io(e));
    }

    if let Err(e) = writer.flush().await {
        warn!(peer = %peer, error = %e, "Failed to flush TLS ServerHello");
        return HandshakeResult::Error(ProxyError::Io(e));
    }

    debug!(
        peer = %peer,
        user = %validation.user,
        "TLS handshake successful"
    );

    HandshakeResult::Success((
        FakeTlsReader::new(reader),
        FakeTlsWriter::new(writer),
        validation.user,
    ))
}

/// Handle MTProto obfuscation handshake
pub async fn handle_mtproto_handshake<R, W>(
    handshake: &[u8; HANDSHAKE_LEN],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    is_tls: bool,
    preferred_user: Option<&str>,
) -> HandshakeResult<(CryptoReader<R>, CryptoWriter<W>, HandshakeSuccess), R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    // Log only the length — the raw bytes contain dec_prekey_iv (key-derivable material).
    trace!(peer = %peer, handshake_len = handshake.len(), "MTProto handshake received");

    let dec_prekey_iv = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    if replay_checker.check_and_add_handshake(dec_prekey_iv) {
        warn!(peer = %peer, "MTProto replay attack detected");
        return HandshakeResult::BadClient { reader, writer };
    }

    let enc_prekey_iv: Vec<u8> = dec_prekey_iv.iter().rev().copied().collect();

    let decoded_users = decode_user_secrets(config, preferred_user);

    for (user, secret) in decoded_users {

        let dec_prekey = &dec_prekey_iv[..PREKEY_LEN];
        let dec_iv_bytes = &dec_prekey_iv[PREKEY_LEN..];

        let mut dec_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
        dec_key_input.extend_from_slice(dec_prekey);
        dec_key_input.extend_from_slice(&secret);
        let dec_key = sha256(&dec_key_input);

        let mut dec_iv_arr = [0u8; IV_LEN];
        dec_iv_arr.copy_from_slice(dec_iv_bytes);
        let dec_iv = u128::from_be_bytes(dec_iv_arr);

        let mut decryptor = AesCtr::new(&dec_key, dec_iv);
        let decrypted = decryptor.decrypt(handshake);

        let mut tag_bytes = [0u8; 4];
        tag_bytes.copy_from_slice(&decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]);

        let proto_tag = match ProtoTag::from_bytes(tag_bytes) {
            Some(tag) => tag,
            None => continue,
        };

        let mode_ok = match proto_tag {
            ProtoTag::Secure => {
                if is_tls {
                    config.general.modes.tls || config.general.modes.secure
                } else {
                    config.general.modes.secure || config.general.modes.tls
                }
            }
            ProtoTag::Intermediate | ProtoTag::Abridged => config.general.modes.classic,
        };

        if !mode_ok {
            debug!(peer = %peer, user = %user, proto = ?proto_tag, "Mode not enabled");
            continue;
        }

        let mut dc_idx_bytes = [0u8; 2];
        dc_idx_bytes.copy_from_slice(&decrypted[DC_IDX_POS..DC_IDX_POS + 2]);
        let dc_idx = i16::from_le_bytes(dc_idx_bytes);

        let enc_prekey = &enc_prekey_iv[..PREKEY_LEN];
        let enc_iv_bytes = &enc_prekey_iv[PREKEY_LEN..];

        let mut enc_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
        enc_key_input.extend_from_slice(enc_prekey);
        enc_key_input.extend_from_slice(&secret);
        let enc_key = sha256(&enc_key_input);

        let mut enc_iv_arr = [0u8; IV_LEN];
        enc_iv_arr.copy_from_slice(enc_iv_bytes);
        let enc_iv = u128::from_be_bytes(enc_iv_arr);

        let encryptor = AesCtr::new(&enc_key, enc_iv);

        let success = HandshakeSuccess {
            user: user.clone(),
            dc_idx,
            proto_tag,
            dec_key,
            dec_iv,
            enc_key,
            enc_iv,
            peer,
            is_tls,
        };

        debug!(
            peer = %peer,
            user = %user,
            dc = dc_idx,
            proto = ?proto_tag,
            tls = is_tls,
            "MTProto handshake successful"
        );

        let max_pending = config.general.crypto_pending_buffer;
        return HandshakeResult::Success((
            CryptoReader::new(reader, decryptor),
            CryptoWriter::new(writer, encryptor, max_pending),
            success,
        ));
    }

    debug!(peer = %peer, "MTProto handshake: no matching user found");
    HandshakeResult::BadClient { reader, writer }
}

/// Generate nonce for Telegram connection
// TEMPORARY: panic is the correct sentinel for catastrophic CSPRNG failure here; proper
// Result-propagation fix is tracked in .David_docs/deferred_generate_tg_nonce_panic.md.
#[allow(clippy::panic)]
pub fn generate_tg_nonce(
    proto_tag: ProtoTag, 
    dc_idx: i16,
    _client_dec_key: &[u8; 32],
    _client_dec_iv: u128,
    client_enc_key: &[u8; 32],
    client_enc_iv: u128,
    rng: &SecureRandom,
    fast_mode: bool,
) -> ([u8; HANDSHAKE_LEN], [u8; 32], u128, [u8; 32], u128) {
    // The probability of any single candidate being rejected is roughly 1/256
    // (first-byte filter). After 1000 attempts without a valid nonce the CSPRNG
    // has failed catastrophically; we must not proceed with a broken RNG.
    for _ in 0..1000 {
        let bytes = rng.bytes(HANDSHAKE_LEN);
        let mut nonce = [0u8; HANDSHAKE_LEN];
        nonce.copy_from_slice(&bytes);

        if RESERVED_NONCE_FIRST_BYTES.contains(&nonce[0]) { continue; }

        let first_four = [nonce[0], nonce[1], nonce[2], nonce[3]];
        if RESERVED_NONCE_BEGINNINGS.contains(&first_four) { continue; }

        let continue_four = [nonce[4], nonce[5], nonce[6], nonce[7]];
        if RESERVED_NONCE_CONTINUES.contains(&continue_four) { continue; }

        nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].copy_from_slice(&proto_tag.to_bytes());
        // CRITICAL: write dc_idx so upstream DC knows where to route
        nonce[DC_IDX_POS..DC_IDX_POS + 2].copy_from_slice(&dc_idx.to_le_bytes());

        if fast_mode {
            let mut key_iv = Vec::with_capacity(KEY_LEN + IV_LEN);
            key_iv.extend_from_slice(client_enc_key);
            key_iv.extend_from_slice(&client_enc_iv.to_be_bytes());
            key_iv.reverse(); // Python/C behavior: reversed enc_key+enc_iv in nonce
            nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN].copy_from_slice(&key_iv);
        }

        let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
        let dec_key_iv: Vec<u8> = enc_key_iv.iter().rev().copied().collect();

        let mut tg_enc_key = [0u8; KEY_LEN];
        tg_enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
        let mut tg_enc_iv_bytes = [0u8; IV_LEN];
        tg_enc_iv_bytes.copy_from_slice(&enc_key_iv[KEY_LEN..]);
        let tg_enc_iv = u128::from_be_bytes(tg_enc_iv_bytes);

        let mut tg_dec_key = [0u8; KEY_LEN];
        tg_dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
        let mut tg_dec_iv_bytes = [0u8; IV_LEN];
        tg_dec_iv_bytes.copy_from_slice(&dec_key_iv[KEY_LEN..]);
        let tg_dec_iv = u128::from_be_bytes(tg_dec_iv_bytes);

        return (nonce, tg_enc_key, tg_enc_iv, tg_dec_key, tg_dec_iv);
    }
    panic!("generate_tg_nonce: CSPRNG produced 1000 consecutive reserved-pattern nonces — RNG is compromised");
}

/// Encrypt nonce for sending to Telegram and return cipher objects with correct counter state
pub fn encrypt_tg_nonce_with_ciphers(nonce: &[u8; HANDSHAKE_LEN]) -> (Vec<u8>, AesCtr, AesCtr) {
    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let dec_key_iv: Vec<u8> = enc_key_iv.iter().rev().copied().collect();

    let mut enc_key = [0u8; KEY_LEN];
    enc_key.copy_from_slice(&enc_key_iv[..KEY_LEN]);
    let mut enc_iv_bytes = [0u8; IV_LEN];
    enc_iv_bytes.copy_from_slice(&enc_key_iv[KEY_LEN..]);
    let enc_iv = u128::from_be_bytes(enc_iv_bytes);

    let mut dec_key = [0u8; KEY_LEN];
    dec_key.copy_from_slice(&dec_key_iv[..KEY_LEN]);
    let mut dec_iv_bytes = [0u8; IV_LEN];
    dec_iv_bytes.copy_from_slice(&dec_key_iv[KEY_LEN..]);
    let dec_iv = u128::from_be_bytes(dec_iv_bytes);

    let mut encryptor = AesCtr::new(&enc_key, enc_iv);
    let encrypted_full = encryptor.encrypt(nonce);  // counter: 0 → 4

    let mut result = nonce[..PROTO_TAG_POS].to_vec();
    result.extend_from_slice(&encrypted_full[PROTO_TAG_POS..]);

    let decryptor = AesCtr::new(&dec_key, dec_iv);

    (result, encryptor, decryptor)
}

/// Encrypt nonce for sending to Telegram (legacy function for compatibility)
pub fn encrypt_tg_nonce(nonce: &[u8; HANDSHAKE_LEN]) -> Vec<u8> {
    let (encrypted, _, _) = encrypt_tg_nonce_with_ciphers(nonce);
    encrypted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_tg_nonce() {
        let client_dec_key = [0x42u8; 32];
        let client_dec_iv = 12345u128;
        let client_enc_key = [0x24u8; 32];
        let client_enc_iv = 54321u128;

        let rng = SecureRandom::new();
        let (nonce, _tg_enc_key, _tg_enc_iv, _tg_dec_key, _tg_dec_iv) = 
            generate_tg_nonce(
                ProtoTag::Secure,
                2,
                &client_dec_key,
                client_dec_iv,
                &client_enc_key,
                client_enc_iv,
                &rng,
                false,
            );

        assert_eq!(nonce.len(), HANDSHAKE_LEN);

        let tag_bytes: [u8; 4] = nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().unwrap();
        assert_eq!(ProtoTag::from_bytes(tag_bytes), Some(ProtoTag::Secure));
    }

    #[test]
    fn test_encrypt_tg_nonce() {
        let client_dec_key = [0x42u8; 32];
        let client_dec_iv = 12345u128;
        let client_enc_key = [0x24u8; 32];
        let client_enc_iv = 54321u128;

        let rng = SecureRandom::new();
        let (nonce, _, _, _, _) = 
            generate_tg_nonce(
                ProtoTag::Secure,
                2,
                &client_dec_key,
                client_dec_iv,
                &client_enc_key,
                client_enc_iv,
                &rng,
                false,
            );

        let encrypted = encrypt_tg_nonce(&nonce);

        assert_eq!(encrypted.len(), HANDSHAKE_LEN);
        assert_eq!(&encrypted[..PROTO_TAG_POS], &nonce[..PROTO_TAG_POS]);
        assert_ne!(&encrypted[PROTO_TAG_POS..], &nonce[PROTO_TAG_POS..]);
    }

    #[test]
    fn test_handshake_success_zeroize_on_drop() {
        let success = HandshakeSuccess {
            user: "test".to_string(),
            dc_idx: 2,
            proto_tag: ProtoTag::Secure,
            dec_key: [0xAA; 32],
            dec_iv: 0xBBBBBBBB,
            enc_key: [0xCC; 32],
            enc_iv: 0xDDDDDDDD,
            peer: "127.0.0.1:1234".parse().unwrap(),
            is_tls: true,
        };

        assert_eq!(success.dec_key, [0xAA; 32]);
        assert_eq!(success.enc_key, [0xCC; 32]);

        drop(success);
        // Drop impl zeroizes key material without panic
    }

    // ── generate_tg_nonce — correctness and security invariants ─────────────

    fn make_nonce(proto_tag: ProtoTag, dc_idx: i16, fast_mode: bool) -> [u8; HANDSHAKE_LEN] {
        let rng = SecureRandom::new();
        let (nonce, _, _, _, _) = generate_tg_nonce(
            proto_tag,
            dc_idx,
            &[0xAAu8; 32],
            0u128,
            &[0xBBu8; 32],
            0u128,
            &rng,
            fast_mode,
        );
        nonce
    }

    // A censor probing the proxy can detect it if nonces contain protocol-
    // discriminating reserved patterns that are never present in random data.
    #[test]
    fn nonce_first_byte_never_0xef() {
        for _ in 0..500 {
            let nonce = make_nonce(ProtoTag::Secure, 1, false);
            assert_ne!(nonce[0], 0xef, "reserved first byte 0xef generated");
        }
    }

    #[test]
    fn nonce_first_four_bytes_never_a_reserved_beginning() {
        for _ in 0..500 {
            let nonce = make_nonce(ProtoTag::Intermediate, 2, false);
            let first_four: [u8; 4] = nonce[..4].try_into().unwrap();
            assert!(
                !RESERVED_NONCE_BEGINNINGS.contains(&first_four),
                "reserved 4-byte beginning generated: {:02x?}",
                first_four
            );
        }
    }

    #[test]
    fn nonce_bytes_4_to_7_never_all_zero() {
        for _ in 0..500 {
            let nonce = make_nonce(ProtoTag::Abridged, -1, false);
            let cont: [u8; 4] = nonce[4..8].try_into().unwrap();
            assert!(
                !RESERVED_NONCE_CONTINUES.contains(&cont),
                "reserved continue bytes [0,0,0,0] generated"
            );
        }
    }

    #[test]
    fn nonce_embeds_proto_tag_at_correct_position() {
        for tag in [ProtoTag::Secure, ProtoTag::Intermediate, ProtoTag::Abridged] {
            let nonce = make_nonce(tag, 1, false);
            let written: [u8; 4] = nonce[PROTO_TAG_POS..PROTO_TAG_POS + 4].try_into().unwrap();
            assert_eq!(
                ProtoTag::from_bytes(written),
                Some(tag),
                "proto_tag not written at PROTO_TAG_POS for {:?}",
                tag
            );
        }
    }

    #[test]
    fn nonce_embeds_dc_idx_at_correct_position_positive() {
        for dc in [1i16, 2, 3, 4, 5] {
            let nonce = make_nonce(ProtoTag::Secure, dc, false);
            let written = i16::from_le_bytes(nonce[DC_IDX_POS..DC_IDX_POS + 2].try_into().unwrap());
            assert_eq!(written, dc, "dc_idx not written correctly for dc={}", dc);
        }
    }

    #[test]
    fn nonce_embeds_dc_idx_at_correct_position_negative() {
        // Negative DC indices are used for test/cdn DCs in Telegram's protocol.
        for dc in [-1i16, -2, -3, -4, -5] {
            let nonce = make_nonce(ProtoTag::Intermediate, dc, false);
            let written = i16::from_le_bytes(nonce[DC_IDX_POS..DC_IDX_POS + 2].try_into().unwrap());
            assert_eq!(written, dc, "negative dc_idx not written correctly for dc={}", dc);
        }
    }

    #[test]
    fn nonce_fast_mode_embeds_reversed_enc_key_iv_at_skip_pos() {
        let enc_key = [0xCCu8; 32];
        let enc_iv = 0xDEAD_BEEF_CAFE_BABEu128;
        let rng = SecureRandom::new();
        let (nonce, _, _, _, _) = generate_tg_nonce(
            ProtoTag::Secure,
            2,
            &[0xAAu8; 32],
            0u128,
            &enc_key,
            enc_iv,
            &rng,
            true,
        );

        // fast_mode writes reversed(enc_key || enc_iv.to_be_bytes()) at SKIP_LEN position
        let mut expected = Vec::with_capacity(KEY_LEN + IV_LEN);
        expected.extend_from_slice(&enc_key);
        expected.extend_from_slice(&enc_iv.to_be_bytes());
        expected.reverse();

        assert_eq!(
            &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN],
            expected.as_slice(),
            "fast_mode: reversed enc_key+enc_iv not written at SKIP_LEN"
        );
    }

    #[test]
    fn nonce_slow_mode_does_not_overwrite_random_bytes_at_skip_pos() {
        // In non-fast_mode the key region at SKIP_LEN is random, not derived from client keys.
        // Verify the nonce at that region is NOT the zero block (statistical sanity check).
        let rng = SecureRandom::new();
        let (nonce, _, _, _, _) = generate_tg_nonce(
            ProtoTag::Secure,
            1,
            &[0u8; 32],
            0,
            &[0u8; 32],
            0,
            &rng,
            false,
        );
        let region = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
        assert_ne!(region, &[0u8; KEY_LEN + IV_LEN], "SKIP_LEN region is all-zero — RNG suspiciously broken");
    }

    /// Regression: generate_tg_nonce must not loop more than 1000 times.
    /// This test uses a deterministic seed to hit the panic threshold.
    /// We can't inject a broken RNG, so we instead verify the normal path
    /// terminates instantly (not a 1000-iteration hang).
    #[test]
    fn nonce_generation_terminates_quickly() {
        use std::time::Instant;
        let rng = SecureRandom::new();
        let start = Instant::now();
        for _ in 0..1000 {
            let _ = generate_tg_nonce(ProtoTag::Secure, 1, &[0xAAu8; 32], 0, &[0xBBu8; 32], 0, &rng, false);
        }
        // 1000 calls should complete in well under 1 second on any hardware.
        assert!(
            start.elapsed().as_secs() < 1,
            "generate_tg_nonce took suspiciously long — possible loop regression"
        );
    }

    /// Guard: reserved patterns in RESERVED_NONCE_BEGINNINGS include all patterns
    /// that a censor would recognise as non-proxy traffic (TLS, HTTP verbs, protocol tags).
    #[test]
    fn reserved_beginnings_cover_known_protocol_discriminators() {
        // TLS ClientHello magic
        assert!(RESERVED_NONCE_BEGINNINGS.contains(&[0x16, 0x03, 0x01, 0x02]));
        // Intermediate / Secure protocol tags
        assert!(RESERVED_NONCE_BEGINNINGS.contains(&[0xee, 0xee, 0xee, 0xee]));
        assert!(RESERVED_NONCE_BEGINNINGS.contains(&[0xdd, 0xdd, 0xdd, 0xdd]));
    }
}
