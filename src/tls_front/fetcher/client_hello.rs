use super::*;

pub(super) fn build_client_config(alpn_protocols: &[&[u8]]) -> Arc<ClientConfig> {
    let root = rustls::RootCertStore::empty();

    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("protocol versions")
        .with_root_certificates(root)
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(NoVerify));
    config.alpn_protocols = alpn_protocols.iter().map(|proto| proto.to_vec()).collect();

    Arc::new(config)
}

pub(super) fn deterministic_bytes(seed: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut chunk_seed = Vec::with_capacity(seed.len() + std::mem::size_of::<u32>());
        chunk_seed.extend_from_slice(seed.as_bytes());
        chunk_seed.extend_from_slice(&counter.to_le_bytes());
        out.extend_from_slice(&sha256(&chunk_seed));
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

pub(super) fn profile_cipher_suites(profile: TlsFetchProfile) -> &'static [u16] {
    const MODERN_CHROME: &[u16] = &[
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c, 0xcca9, 0xc02f, 0xc030, 0xcca8, 0x009e, 0x00ff,
    ];
    const MODERN_FIREFOX: &[u16] = &[
        0x1301, 0x1303, 0x1302, 0xc02b, 0xcca9, 0xc02c, 0xc02f, 0xcca8, 0xc030, 0x009e, 0x00ff,
    ];
    const COMPAT_TLS12: &[u16] = &[
        0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca9, 0xcca8, 0x1301, 0x1302, 0x1303, 0x009e, 0x00ff,
    ];
    const LEGACY_MINIMAL: &[u16] = &[0xc02b, 0xc02f, 0x1301, 0x1302, 0x00ff];

    match profile {
        TlsFetchProfile::ModernChromeLike => MODERN_CHROME,
        TlsFetchProfile::ModernFirefoxLike => MODERN_FIREFOX,
        TlsFetchProfile::CompatTls12 => COMPAT_TLS12,
        TlsFetchProfile::LegacyMinimal => LEGACY_MINIMAL,
    }
}

pub(super) fn profile_groups(profile: TlsFetchProfile) -> &'static [u16] {
    const MODERN: &[u16] = &[
        TLS_NAMED_GROUP_X25519MLKEM768,
        TLS_NAMED_GROUP_X25519,
        0x0017,
        0x0018,
    ];
    const COMPAT: &[u16] = &[TLS_NAMED_GROUP_X25519, 0x0017];
    const LEGACY: &[u16] = &[0x0017];

    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => MODERN,
        TlsFetchProfile::CompatTls12 => COMPAT,
        TlsFetchProfile::LegacyMinimal => LEGACY,
    }
}

pub(super) fn profile_sig_algs(profile: TlsFetchProfile) -> &'static [u16] {
    const MODERN: &[u16] = &[0x0804, 0x0805, 0x0403, 0x0503, 0x0806];
    const COMPAT: &[u16] = &[0x0403, 0x0503, 0x0804, 0x0805];
    const LEGACY: &[u16] = &[0x0403, 0x0804];

    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => MODERN,
        TlsFetchProfile::CompatTls12 => COMPAT,
        TlsFetchProfile::LegacyMinimal => LEGACY,
    }
}

pub(super) fn profile_alpn(profile: TlsFetchProfile) -> &'static [&'static [u8]] {
    const H2_HTTP11: &[&[u8]] = &[b"h2", b"http/1.1"];
    const HTTP11: &[&[u8]] = &[b"http/1.1"];
    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => H2_HTTP11,
        TlsFetchProfile::CompatTls12 | TlsFetchProfile::LegacyMinimal => HTTP11,
    }
}

pub(super) fn profile_alpn_labels(profile: TlsFetchProfile) -> &'static [&'static str] {
    const H2_HTTP11: &[&str] = &["h2", "http/1.1"];
    const HTTP11: &[&str] = &["http/1.1"];
    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => H2_HTTP11,
        TlsFetchProfile::CompatTls12 | TlsFetchProfile::LegacyMinimal => HTTP11,
    }
}

pub(super) fn profile_session_id_len(profile: TlsFetchProfile) -> usize {
    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => 32,
        TlsFetchProfile::CompatTls12 | TlsFetchProfile::LegacyMinimal => 0,
    }
}

pub(super) fn profile_supported_versions(profile: TlsFetchProfile) -> &'static [u16] {
    const MODERN: &[u16] = &[0x0304, 0x0303];
    const COMPAT: &[u16] = &[0x0303, 0x0304];
    const LEGACY: &[u16] = &[0x0303];
    match profile {
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike => MODERN,
        TlsFetchProfile::CompatTls12 => COMPAT,
        TlsFetchProfile::LegacyMinimal => LEGACY,
    }
}

pub(super) fn profile_padding_target(profile: TlsFetchProfile) -> usize {
    match profile {
        // X25519MLKEM768 makes the Chrome-like ClientHello much larger than
        // legacy pre-hybrid profiles; keep enough headroom for padding.
        TlsFetchProfile::ModernChromeLike => 1450,
        TlsFetchProfile::ModernFirefoxLike => 200,
        TlsFetchProfile::CompatTls12 => 180,
        TlsFetchProfile::LegacyMinimal => 64,
    }
}

pub(super) fn grease_value(rng: &SecureRandom, deterministic: bool, seed: &str) -> u16 {
    const GREASE_VALUES: [u16; 16] = [
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa,
        0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    if deterministic {
        let idx = deterministic_bytes(seed, 1)[0] as usize % GREASE_VALUES.len();
        GREASE_VALUES[idx]
    } else {
        let idx = (rng.bytes(1)[0] as usize) % GREASE_VALUES.len();
        GREASE_VALUES[idx]
    }
}

pub(super) fn gen_mlkem768_client_encapsulation_key(
    rng: &SecureRandom,
    deterministic: bool,
    seed: &str,
) -> Option<Vec<u8>> {
    let seed_bytes = if deterministic {
        deterministic_bytes(seed, 64)
    } else {
        rng.bytes(64)
    };
    let seed = MlKemSeed::try_from(seed_bytes.as_slice()).ok()?;
    let decapsulation_key = MlKemDecapsulationKey::<MlKem768>::from_seed(seed);
    let encapsulation_key = decapsulation_key.encapsulation_key().to_bytes();
    let bytes = encapsulation_key.as_slice();
    if bytes.len() == MLKEM768_CLIENT_ENCAPSULATION_KEY_LEN {
        Some(bytes.to_vec())
    } else {
        None
    }
}

pub(super) fn gen_x25519mlkem768_client_key_share(
    rng: &SecureRandom,
    deterministic: bool,
    seed: &str,
) -> Option<Vec<u8>> {
    let mlkem_key =
        gen_mlkem768_client_encapsulation_key(rng, deterministic, &format!("{seed}:mlkem768"))?;
    let x25519_key = gen_key_share(rng, deterministic, &format!("{seed}:x25519"));
    let mut key_share =
        Vec::with_capacity(MLKEM768_CLIENT_ENCAPSULATION_KEY_LEN + x25519_key.len());
    key_share.extend_from_slice(&mlkem_key);
    key_share.extend_from_slice(&x25519_key);
    Some(key_share)
}

pub(super) fn push_client_key_share_entry(keyshare: &mut Vec<u8>, group: u16, key: &[u8]) {
    keyshare.extend_from_slice(&group.to_be_bytes());
    keyshare.extend_from_slice(&(key.len() as u16).to_be_bytes());
    keyshare.extend_from_slice(key);
}

pub(super) fn build_client_hello(
    sni: &str,
    rng: &SecureRandom,
    profile: TlsFetchProfile,
    grease_enabled: bool,
    deterministic: bool,
) -> Vec<u8> {
    // === ClientHello body ===
    let mut body = Vec::new();

    // Legacy version (TLS 1.0) as in real ClientHello headers
    body.extend_from_slice(&[0x03, 0x03]);

    // Random
    if deterministic {
        body.extend_from_slice(&deterministic_bytes(&format!("tls-fetch-random:{sni}"), 32));
    } else {
        body.extend_from_slice(&rng.bytes(32));
    }

    // Use non-empty Session ID for modern TLS 1.3-like profiles to reduce middlebox friction.
    let session_id_len = profile_session_id_len(profile);
    let session_id = if session_id_len == 0 {
        Vec::new()
    } else if deterministic {
        deterministic_bytes(
            &format!("tls-fetch-session:{sni}:{}", profile.as_str()),
            session_id_len,
        )
    } else {
        rng.bytes(session_id_len)
    };
    body.push(session_id.len() as u8);
    body.extend_from_slice(&session_id);

    let mut cipher_suites = profile_cipher_suites(profile).to_vec();
    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("cipher:{sni}"));
        cipher_suites.insert(0, grease);
    }
    body.extend_from_slice(&((cipher_suites.len() * 2) as u16).to_be_bytes());
    for suite in cipher_suites {
        body.extend_from_slice(&suite.to_be_bytes());
    }

    // Compression methods: null only
    body.push(1);
    body.push(0);

    // === Extensions ===
    let mut exts = Vec::new();

    let mut push_extension = |ext_type: u16, data: &[u8]| {
        exts.extend_from_slice(&ext_type.to_be_bytes());
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(data);
    };

    // server_name (SNI)
    let sni_bytes = sni.as_bytes();
    let mut sni_ext = Vec::with_capacity(5 + sni_bytes.len());
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16 + 3).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(sni_bytes);
    push_extension(0x0000, &sni_ext);

    // Chrome-like profile keeps browser-like ordering and extension set.
    if matches!(profile, TlsFetchProfile::ModernChromeLike) {
        // ec_point_formats: uncompressed only.
        push_extension(0x000b, &[0x01, 0x00]);
    }

    // supported_groups
    let mut groups = profile_groups(profile).to_vec();
    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("group:{sni}"));
        groups.insert(0, grease);
    }
    let mut groups_ext = Vec::with_capacity(2 + groups.len() * 2);
    groups_ext.extend_from_slice(&(groups.len() as u16 * 2).to_be_bytes());
    for g in groups {
        groups_ext.extend_from_slice(&g.to_be_bytes());
    }
    push_extension(0x000a, &groups_ext);

    if matches!(profile, TlsFetchProfile::ModernChromeLike) {
        // session_ticket
        push_extension(0x0023, &[]);
    }

    // signature_algorithms
    let mut sig_algs = profile_sig_algs(profile).to_vec();
    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("sigalg:{sni}"));
        sig_algs.insert(0, grease);
    }
    let mut sig_algs_ext = Vec::with_capacity(2 + sig_algs.len() * 2);
    sig_algs_ext.extend_from_slice(&(sig_algs.len() as u16 * 2).to_be_bytes());
    for a in sig_algs {
        sig_algs_ext.extend_from_slice(&a.to_be_bytes());
    }
    push_extension(0x000d, &sig_algs_ext);

    // supported_versions
    let mut versions = profile_supported_versions(profile).to_vec();
    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("version:{sni}"));
        versions.insert(0, grease);
    }
    let mut versions_ext = Vec::with_capacity(1 + versions.len() * 2);
    versions_ext.push((versions.len() * 2) as u8);
    for v in versions {
        versions_ext.extend_from_slice(&v.to_be_bytes());
    }
    push_extension(0x002b, &versions_ext);

    if matches!(profile, TlsFetchProfile::ModernChromeLike) {
        // psk_key_exchange_modes: psk_dhe_ke
        push_extension(0x002d, &[0x01, 0x01]);
    }

    // key_share
    let key_share_seed = format!("tls-fetch-keyshare:{sni}:{}", profile.as_str());
    let mut keyshare = Vec::new();
    if matches!(
        profile,
        TlsFetchProfile::ModernChromeLike | TlsFetchProfile::ModernFirefoxLike
    ) {
        if let Some(key) = gen_x25519mlkem768_client_key_share(rng, deterministic, &key_share_seed)
        {
            push_client_key_share_entry(&mut keyshare, TLS_NAMED_GROUP_X25519MLKEM768, &key);
        }
    }
    let key = gen_key_share(rng, deterministic, &key_share_seed);
    push_client_key_share_entry(&mut keyshare, TLS_NAMED_GROUP_X25519, &key);
    let mut keyshare_ext = Vec::with_capacity(2 + keyshare.len());
    keyshare_ext.extend_from_slice(&(keyshare.len() as u16).to_be_bytes());
    keyshare_ext.extend_from_slice(&keyshare);
    push_extension(0x0033, &keyshare_ext);

    // ALPN
    let mut alpn_list = Vec::new();
    for proto in profile_alpn(profile) {
        alpn_list.push(proto.len() as u8);
        alpn_list.extend_from_slice(proto);
    }
    if !alpn_list.is_empty() {
        let mut alpn_ext = Vec::with_capacity(2 + alpn_list.len());
        alpn_ext.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
        alpn_ext.extend_from_slice(&alpn_list);
        push_extension(0x0010, &alpn_ext);
    }

    if grease_enabled {
        let grease = grease_value(rng, deterministic, &format!("ext:{sni}"));
        push_extension(grease, &[]);
    }

    // padding to reduce recognizability and keep length ~500 bytes
    let target_ext_len = profile_padding_target(profile);
    if exts.len() < target_ext_len {
        let remaining = target_ext_len - exts.len();
        if remaining > 4 {
            let pad_len = remaining - 4; // minus type+len
            exts.extend_from_slice(&0x0015u16.to_be_bytes()); // padding extension
            exts.extend_from_slice(&(pad_len as u16).to_be_bytes());
            exts.resize(exts.len() + pad_len, 0);
        }
    }

    // Extensions length prefix
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    // === Handshake wrapper ===
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    let len_bytes = (body.len() as u32).to_be_bytes();
    handshake.extend_from_slice(&len_bytes[1..4]);
    handshake.extend_from_slice(&body);

    // === Record ===
    let mut record = Vec::new();
    record.push(TLS_RECORD_HANDSHAKE);
    record.extend_from_slice(&[0x03, 0x01]); // legacy record version
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

pub(super) fn gen_key_share(rng: &SecureRandom, deterministic: bool, seed: &str) -> [u8; 32] {
    let mut scalar = [0u8; 32];
    if deterministic {
        scalar.copy_from_slice(&deterministic_bytes(seed, 32));
    } else {
        scalar.copy_from_slice(&rng.bytes(32));
    }
    x25519(scalar, X25519_BASEPOINT_BYTES)
}
