//! MTProto Handshake

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn, trace, info};
use zeroize::Zeroize;

use crate::crypto::{sha256, AesCtr, SecureRandom};
use crate::protocol::constants::*;
use crate::protocol::tls;
use crate::stream::{FakeTlsReader, FakeTlsWriter, CryptoReader, CryptoWriter};
use crate::error::{ProxyError, HandshakeResult};
use crate::stats::ReplayChecker;
use crate::config::ProxyConfig;
use crate::tls_front::{TlsFrontCache, emulator};

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

    let secrets: Vec<(String, Vec<u8>)> = config.access.users.iter()
        .filter_map(|(name, hex)| {
            hex::decode(hex).ok().map(|bytes| (name.clone(), bytes))
        })
        .collect();

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
            if let Some(sni) = tls::extract_sni_from_client_hello(handshake) {
                Some(cache.get(&sni).await)
            } else {
                Some(cache.get(&config.censorship.tls_domain).await)
            }
        } else {
            None
        }
    } else {
        None
    };

    let response = if let Some(cached_entry) = cached {
        emulator::build_emulated_server_hello(
            secret,
            &validation.digest,
            &validation.session_id,
            &cached_entry,
            rng,
        )
    } else {
        tls::build_server_hello(
            secret,
            &validation.digest,
            &validation.session_id,
            config.censorship.fake_cert_len,
            rng,
        )
    };

    debug!(peer = %peer, response_len = response.len(), "Sending TLS ServerHello");

    if let Err(e) = writer.write_all(&response).await {
        warn!(peer = %peer, error = %e, "Failed to write TLS ServerHello");
        return HandshakeResult::Error(ProxyError::Io(e));
    }

    if let Err(e) = writer.flush().await {
        warn!(peer = %peer, error = %e, "Failed to flush TLS ServerHello");
        return HandshakeResult::Error(ProxyError::Io(e));
    }

    info!(
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
) -> HandshakeResult<(CryptoReader<R>, CryptoWriter<W>, HandshakeSuccess), R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    trace!(peer = %peer, handshake = ?hex::encode(handshake), "MTProto handshake bytes");

    let dec_prekey_iv = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];

    if replay_checker.check_and_add_handshake(dec_prekey_iv) {
        warn!(peer = %peer, "MTProto replay attack detected");
        return HandshakeResult::BadClient { reader, writer };
    }

    let enc_prekey_iv: Vec<u8> = dec_prekey_iv.iter().rev().copied().collect();

    for (user, secret_hex) in &config.access.users {
        let secret = match hex::decode(secret_hex) {
            Ok(s) => s,
            Err(_) => continue,
        };

        let dec_prekey = &dec_prekey_iv[..PREKEY_LEN];
        let dec_iv_bytes = &dec_prekey_iv[PREKEY_LEN..];

        let mut dec_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
        dec_key_input.extend_from_slice(dec_prekey);
        dec_key_input.extend_from_slice(&secret);
        let dec_key = sha256(&dec_key_input);

        let dec_iv = u128::from_be_bytes(dec_iv_bytes.try_into().unwrap());

        let mut decryptor = AesCtr::new(&dec_key, dec_iv);
        let decrypted = decryptor.decrypt(handshake);

        let tag_bytes: [u8; 4] = decrypted[PROTO_TAG_POS..PROTO_TAG_POS + 4]
            .try_into()
            .unwrap();

        let proto_tag = match ProtoTag::from_bytes(tag_bytes) {
            Some(tag) => tag,
            None => continue,
        };

        let mode_ok = match proto_tag {
            ProtoTag::Secure => {
                if is_tls { config.general.modes.tls } else { config.general.modes.secure }
            }
            ProtoTag::Intermediate | ProtoTag::Abridged => config.general.modes.classic,
        };

        if !mode_ok {
            debug!(peer = %peer, user = %user, proto = ?proto_tag, "Mode not enabled");
            continue;
        }

        let dc_idx = i16::from_le_bytes(
            decrypted[DC_IDX_POS..DC_IDX_POS + 2].try_into().unwrap()
        );

        let enc_prekey = &enc_prekey_iv[..PREKEY_LEN];
        let enc_iv_bytes = &enc_prekey_iv[PREKEY_LEN..];

        let mut enc_key_input = Vec::with_capacity(PREKEY_LEN + secret.len());
        enc_key_input.extend_from_slice(enc_prekey);
        enc_key_input.extend_from_slice(&secret);
        let enc_key = sha256(&enc_key_input);

        let enc_iv = u128::from_be_bytes(enc_iv_bytes.try_into().unwrap());

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

        info!(
            peer = %peer,
            user = %user,
            dc = dc_idx,
            proto = ?proto_tag,
            tls = is_tls,
            "MTProto handshake successful"
        );

        return HandshakeResult::Success((
            CryptoReader::new(reader, decryptor),
            CryptoWriter::new(writer, encryptor),
            success,
        ));
    }

    debug!(peer = %peer, "MTProto handshake: no matching user found");
    HandshakeResult::BadClient { reader, writer }
}

/// Generate nonce for Telegram connection
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
    loop {
        let bytes = rng.bytes(HANDSHAKE_LEN);
        let mut nonce: [u8; HANDSHAKE_LEN] = bytes.try_into().unwrap();

        if RESERVED_NONCE_FIRST_BYTES.contains(&nonce[0]) { continue; }

        let first_four: [u8; 4] = nonce[..4].try_into().unwrap();
        if RESERVED_NONCE_BEGINNINGS.contains(&first_four) { continue; }

        let continue_four: [u8; 4] = nonce[4..8].try_into().unwrap();
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

        let tg_enc_key: [u8; 32] = enc_key_iv[..KEY_LEN].try_into().unwrap();
        let tg_enc_iv = u128::from_be_bytes(enc_key_iv[KEY_LEN..].try_into().unwrap());

        let tg_dec_key: [u8; 32] = dec_key_iv[..KEY_LEN].try_into().unwrap();
        let tg_dec_iv = u128::from_be_bytes(dec_key_iv[KEY_LEN..].try_into().unwrap());

        return (nonce, tg_enc_key, tg_enc_iv, tg_dec_key, tg_dec_iv);
    }
}

/// Encrypt nonce for sending to Telegram and return cipher objects with correct counter state
pub fn encrypt_tg_nonce_with_ciphers(nonce: &[u8; HANDSHAKE_LEN]) -> (Vec<u8>, AesCtr, AesCtr) {
    let enc_key_iv = &nonce[SKIP_LEN..SKIP_LEN + KEY_LEN + IV_LEN];
    let dec_key_iv: Vec<u8> = enc_key_iv.iter().rev().copied().collect();

    let enc_key: [u8; 32] = enc_key_iv[..KEY_LEN].try_into().unwrap();
    let enc_iv = u128::from_be_bytes(enc_key_iv[KEY_LEN..].try_into().unwrap());

    let dec_key: [u8; 32] = dec_key_iv[..KEY_LEN].try_into().unwrap();
    let dec_iv = u128::from_be_bytes(dec_key_iv[KEY_LEN..].try_into().unwrap());

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
}
