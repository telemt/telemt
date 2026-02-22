//! Protocol constants and datacenter addresses

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::crypto::SecureRandom;
use std::sync::LazyLock;

// ============= Telegram Datacenters =============

pub const TG_DATACENTER_PORT: u16 = 443;

pub static TG_DATACENTERS_V4: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    vec![
        IpAddr::V4(Ipv4Addr::new(149, 154, 175, 50)),
        IpAddr::V4(Ipv4Addr::new(149, 154, 167, 51)),
        IpAddr::V4(Ipv4Addr::new(149, 154, 175, 100)),
        IpAddr::V4(Ipv4Addr::new(149, 154, 167, 91)),
        IpAddr::V4(Ipv4Addr::new(149, 154, 171, 5)),
    ]
});

pub static TG_DATACENTERS_V6: LazyLock<Vec<IpAddr>> = LazyLock::new(|| {
    vec![
        IpAddr::V6("2001:b28:f23d:f001::a".parse().unwrap()),
        IpAddr::V6("2001:67c:04e8:f002::a".parse().unwrap()),
        IpAddr::V6("2001:b28:f23d:f003::a".parse().unwrap()),
        IpAddr::V6("2001:67c:04e8:f004::a".parse().unwrap()),
        IpAddr::V6("2001:b28:f23f:f005::a".parse().unwrap()),
    ]
});

// ============= Middle Proxies (for advertising) =============

pub static TG_MIDDLE_PROXIES_V4: LazyLock<std::collections::HashMap<i32, Vec<(IpAddr, u16)>>> = 
    LazyLock::new(|| {
        let mut m = std::collections::HashMap::new();
        m.insert(1, vec![(IpAddr::V4(Ipv4Addr::new(149, 154, 175, 50)), 8888)]);
        m.insert(-1, vec![(IpAddr::V4(Ipv4Addr::new(149, 154, 175, 50)), 8888)]);
        m.insert(2, vec![(IpAddr::V4(Ipv4Addr::new(149, 154, 161, 144)), 8888)]);
        m.insert(-2, vec![(IpAddr::V4(Ipv4Addr::new(149, 154, 161, 144)), 8888)]);
        m.insert(3, vec![(IpAddr::V4(Ipv4Addr::new(149, 154, 175, 100)), 8888)]);
        m.insert(-3, vec![(IpAddr::V4(Ipv4Addr::new(149, 154, 175, 100)), 8888)]);
        m.insert(4, vec![(IpAddr::V4(Ipv4Addr::new(91, 108, 4, 136)), 8888)]);
        m.insert(-4, vec![(IpAddr::V4(Ipv4Addr::new(149, 154, 165, 109)), 8888)]);
        m.insert(5, vec![(IpAddr::V4(Ipv4Addr::new(91, 108, 56, 183)), 8888)]);
        m.insert(-5, vec![(IpAddr::V4(Ipv4Addr::new(91, 108, 56, 183)), 8888)]);
        m
    });

pub static TG_MIDDLE_PROXIES_V6: LazyLock<std::collections::HashMap<i32, Vec<(IpAddr, u16)>>> = 
    LazyLock::new(|| {
        let mut m = std::collections::HashMap::new();
        m.insert(1, vec![(IpAddr::V6("2001:b28:f23d:f001::d".parse().unwrap()), 8888)]);
        m.insert(-1, vec![(IpAddr::V6("2001:b28:f23d:f001::d".parse().unwrap()), 8888)]);
        m.insert(2, vec![(IpAddr::V6("2001:67c:04e8:f002::d".parse().unwrap()), 80)]);
        m.insert(-2, vec![(IpAddr::V6("2001:67c:04e8:f002::d".parse().unwrap()), 80)]);
        m.insert(3, vec![(IpAddr::V6("2001:b28:f23d:f003::d".parse().unwrap()), 8888)]);
        m.insert(-3, vec![(IpAddr::V6("2001:b28:f23d:f003::d".parse().unwrap()), 8888)]);
        m.insert(4, vec![(IpAddr::V6("2001:67c:04e8:f004::d".parse().unwrap()), 8888)]);
        m.insert(-4, vec![(IpAddr::V6("2001:67c:04e8:f004::d".parse().unwrap()), 8888)]);
        m.insert(5, vec![(IpAddr::V6("2001:b28:f23f:f005::d".parse().unwrap()), 8888)]);
        m.insert(-5, vec![(IpAddr::V6("2001:b28:f23f:f005::d".parse().unwrap()), 8888)]);
        m
    });

// ============= Protocol Tags =============

/// MTProto transport protocol variants
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ProtoTag {
    /// Abridged protocol - compact framing
    Abridged = 0xefefefef,
    /// Intermediate protocol - simple 4-byte length prefix
    Intermediate = 0xeeeeeeee,
    /// Secure intermediate - with random padding
    Secure = 0xdddddddd,
}

impl ProtoTag {
    /// Parse protocol tag from 4 bytes
    pub fn from_bytes(bytes: [u8; 4]) -> Option<Self> {
        match u32::from_le_bytes(bytes) {
            0xefefefef => Some(ProtoTag::Abridged),
            0xeeeeeeee => Some(ProtoTag::Intermediate),
            0xdddddddd => Some(ProtoTag::Secure),
            _ => None,
        }
    }
    
    /// Convert to 4 bytes (little-endian)
    pub fn to_bytes(self) -> [u8; 4] {
        (self as u32).to_le_bytes()
    }
    
    /// Get protocol tag as bytes slice
    pub fn as_bytes(&self) -> &'static [u8; 4] {
        match self {
            ProtoTag::Abridged => &PROTO_TAG_ABRIDGED,
            ProtoTag::Intermediate => &PROTO_TAG_INTERMEDIATE,
            ProtoTag::Secure => &PROTO_TAG_SECURE,
        }
    }
}

/// Protocol tag bytes
pub const PROTO_TAG_ABRIDGED: [u8; 4] = [0xef, 0xef, 0xef, 0xef];
pub const PROTO_TAG_INTERMEDIATE: [u8; 4] = [0xee, 0xee, 0xee, 0xee];
pub const PROTO_TAG_SECURE: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

// ============= Handshake Layout =============

/// Bytes to skip at the start of handshake
pub const SKIP_LEN: usize = 8;
/// Pre-key length (before hashing with secret)
pub const PREKEY_LEN: usize = 32;
/// AES key length
pub const KEY_LEN: usize = 32;
/// AES IV length  
pub const IV_LEN: usize = 16;
/// Total handshake length
pub const HANDSHAKE_LEN: usize = 64;
/// Position of protocol tag in decrypted handshake
pub const PROTO_TAG_POS: usize = 56;
/// Position of datacenter index
pub const DC_IDX_POS: usize = 60;

// ============= Message Limits =============

/// Minimum message length
pub const MIN_MSG_LEN: usize = 12;
/// Maximum message length (16 MB)
pub const MAX_MSG_LEN: usize = 1 << 24;
/// CBC block padding size
pub const CBC_PADDING: usize = 16;
/// Padding filler bytes
pub const PADDING_FILLER: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

// ============= TLS Constants =============

/// Minimum certificate length for detection
pub const MIN_CERT_LEN: usize = 1024;
/// TLS 1.3 version bytes
pub const TLS_VERSION: [u8; 2] = [0x03, 0x03];
/// TLS record type: Handshake
pub const TLS_RECORD_HANDSHAKE: u8 = 0x16;
/// TLS record type: Change Cipher Spec
pub const TLS_RECORD_CHANGE_CIPHER: u8 = 0x14;
/// TLS record type: Application Data
pub const TLS_RECORD_APPLICATION: u8 = 0x17;
/// TLS record type: Alert
pub const TLS_RECORD_ALERT: u8 = 0x15;
/// Maximum TLS record size
pub const MAX_TLS_RECORD_SIZE: usize = 16384;
/// Maximum TLS chunk size (with overhead)
/// RFC 8446 §5.2 allows up to 16384 + 256 bytes of ciphertext
pub const MAX_TLS_CHUNK_SIZE: usize = 16384 + 256;

/// Generate padding length for Secure Intermediate protocol.
/// Total (data + padding) must not be divisible by 4 per MTProto spec.
pub fn secure_padding_len(data_len: usize, rng: &SecureRandom) -> usize {
    let rem = data_len % 4;
    match rem {
        0 => (rng.range(3) + 1) as usize,           // {1, 2, 3}
        1 => rng.range(3) as usize,                 // {0, 1, 2}
        2 => [0usize, 1, 3][rng.range(3) as usize], // {0, 1, 3}
        3 => [0usize, 2, 3][rng.range(3) as usize], // {0, 2, 3}
        _ => unreachable!(),
    }
}

// ============= Timeouts =============

/// Default handshake timeout in seconds
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
/// Default connect timeout in seconds
pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
/// Default keepalive interval in seconds
pub const DEFAULT_KEEPALIVE_SECS: u64 = 600;
/// Default ACK timeout in seconds
pub const DEFAULT_ACK_TIMEOUT_SECS: u64 = 300;

// ============= Buffer Sizes =============

/// Default buffer size
pub const DEFAULT_BUFFER_SIZE: usize = 16384;

/// Small buffer size for bad client handling
pub const SMALL_BUFFER_SIZE: usize = 8192;

// ============= Statistics =============

/// Duration buckets for histogram metrics
pub static DURATION_BUCKETS: &[f64] = &[
    0.1, 0.5, 1.0, 2.0, 5.0, 15.0, 60.0, 300.0, 600.0, 1800.0,
];

// ============= Reserved Nonce Patterns =============

/// Reserved first bytes of nonce (must avoid)
pub static RESERVED_NONCE_FIRST_BYTES: &[u8] = &[0xef];

/// Reserved 4-byte beginnings of nonce
pub static RESERVED_NONCE_BEGINNINGS: &[[u8; 4]] = &[
    [0x48, 0x45, 0x41, 0x44], // HEAD
    [0x50, 0x4F, 0x53, 0x54], // POST
    [0x47, 0x45, 0x54, 0x20], // GET 
    [0xee, 0xee, 0xee, 0xee], // Intermediate
    [0xdd, 0xdd, 0xdd, 0xdd], // Secure
    [0x16, 0x03, 0x01, 0x02], // TLS
];

/// Reserved continuation bytes (bytes 4-7)
pub static RESERVED_NONCE_CONTINUES: &[[u8; 4]] = &[
    [0x00, 0x00, 0x00, 0x00],
];

// ============= RPC Constants (for Middle Proxy) =============

/// RPC Proxy Request

/// RPC Flags (from Erlang mtp_rpc.erl)
pub const RPC_FLAG_NOT_ENCRYPTED: u32 = 0x2;
pub const RPC_FLAG_HAS_AD_TAG: u32    = 0x8;
pub const RPC_FLAG_MAGIC: u32          = 0x1000;
pub const RPC_FLAG_EXTMODE2: u32       = 0x20000;
pub const RPC_FLAG_PAD: u32            = 0x8000000;
pub const RPC_FLAG_INTERMEDIATE: u32   = 0x20000000;
pub const RPC_FLAG_ABRIDGED: u32       = 0x40000000;
pub const RPC_FLAG_QUICKACK: u32       = 0x80000000;

pub const RPC_PROXY_REQ: [u8; 4] = [0xee, 0xf1, 0xce, 0x36];
/// RPC Proxy Answer
pub const RPC_PROXY_ANS: [u8; 4] = [0x0d, 0xda, 0x03, 0x44];
/// RPC Close Extended
pub const RPC_CLOSE_EXT: [u8; 4] = [0xa2, 0x34, 0xb6, 0x5e];
/// RPC Simple ACK
pub const RPC_SIMPLE_ACK: [u8; 4] = [0x9b, 0x40, 0xac, 0x3b];
/// RPC Unknown
pub const RPC_UNKNOWN: [u8; 4] = [0xdf, 0xa2, 0x30, 0x57];
/// RPC Handshake
pub const RPC_HANDSHAKE: [u8; 4] = [0xf5, 0xee, 0x82, 0x76];
/// RPC Nonce
pub const RPC_NONCE: [u8; 4] = [0xaa, 0x87, 0xcb, 0x7a];

/// RPC Flags
pub mod rpc_flags {
    pub const FLAG_NOT_ENCRYPTED: u32 = 0x2;
    pub const FLAG_HAS_AD_TAG: u32 = 0x8;
    pub const FLAG_MAGIC: u32 = 0x1000;
    pub const FLAG_EXTMODE2: u32 = 0x20000;
    pub const FLAG_PAD: u32 = 0x8000000;
    pub const FLAG_INTERMEDIATE: u32 = 0x20000000;
    pub const FLAG_ABRIDGED: u32 = 0x40000000;
    pub const FLAG_QUICKACK: u32 = 0x80000000;
}


    // ============= Middle-End Proxy Servers =============
    pub const ME_PROXY_PORT: u16 = 8888;
    
    pub static TG_MIDDLE_PROXIES_FLAT_V4: LazyLock<Vec<(IpAddr, u16)>> = LazyLock::new(|| {
        vec![
            (IpAddr::V4(Ipv4Addr::new(149, 154, 175, 50)), 8888),
            (IpAddr::V4(Ipv4Addr::new(149, 154, 161, 144)), 8888),
            (IpAddr::V4(Ipv4Addr::new(149, 154, 175, 100)), 8888),
            (IpAddr::V4(Ipv4Addr::new(91, 108, 4, 136)), 8888),
            (IpAddr::V4(Ipv4Addr::new(91, 108, 56, 183)), 8888),
        ]
    });
    
    // ============= RPC Constants (u32 native endian) =============
    // From mtproto-common.h + net-tcp-rpc-common.h + mtproto-proxy.c
    
    pub const RPC_NONCE_U32: u32           = 0x7acb87aa;
    pub const RPC_HANDSHAKE_U32: u32       = 0x7682eef5;
    pub const RPC_HANDSHAKE_ERROR_U32: u32 = 0x6a27beda;
    pub const TL_PROXY_TAG_U32: u32        = 0xdb1e26ae;  // mtproto-proxy.c:121
    
    // mtproto-common.h
    pub const RPC_PROXY_REQ_U32: u32       = 0x36cef1ee;
    pub const RPC_PROXY_ANS_U32: u32       = 0x4403da0d;
    pub const RPC_CLOSE_CONN_U32: u32      = 0x1fcf425d;
    pub const RPC_CLOSE_EXT_U32: u32       = 0x5eb634a2;
    pub const RPC_SIMPLE_ACK_U32: u32      = 0x3bac409b;
    pub const RPC_PING_U32: u32            = 0x5730a2df;
    pub const RPC_PONG_U32: u32            = 0x8430eaa7;
    
    pub const RPC_CRYPTO_NONE_U32: u32 = 0;
    pub const RPC_CRYPTO_AES_U32: u32  = 1;
    
    pub mod proxy_flags {
        pub const FLAG_HAS_AD_TAG: u32    = 1;
        pub const FLAG_NOT_ENCRYPTED: u32 = 0x2;
        pub const FLAG_HAS_AD_TAG2: u32   = 0x8;
        pub const FLAG_MAGIC: u32         = 0x1000;
        pub const FLAG_EXTMODE2: u32      = 0x20000;
        pub const FLAG_PAD: u32           = 0x8000000;
        pub const FLAG_INTERMEDIATE: u32  = 0x20000000;
        pub const FLAG_ABRIDGED: u32      = 0x40000000;
        pub const FLAG_QUICKACK: u32      = 0x80000000;
    }
    
    pub const ME_CONNECT_TIMEOUT_SECS: u64 = 5;
    pub const ME_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
    
    #[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_proto_tag_roundtrip() {
        for tag in [ProtoTag::Abridged, ProtoTag::Intermediate, ProtoTag::Secure] {
            let bytes = tag.to_bytes();
            let parsed = ProtoTag::from_bytes(bytes).unwrap();
            assert_eq!(tag, parsed);
        }
    }
    
    #[test]
    fn test_proto_tag_values() {
        assert_eq!(ProtoTag::Abridged.to_bytes(), PROTO_TAG_ABRIDGED);
        assert_eq!(ProtoTag::Intermediate.to_bytes(), PROTO_TAG_INTERMEDIATE);
        assert_eq!(ProtoTag::Secure.to_bytes(), PROTO_TAG_SECURE);
    }
    
    #[test]
    fn test_invalid_proto_tag() {
        assert!(ProtoTag::from_bytes([0, 0, 0, 0]).is_none());
        assert!(ProtoTag::from_bytes([0xff, 0xff, 0xff, 0xff]).is_none());
    }
    
    #[test]
    fn test_datacenters_count() {
        assert_eq!(TG_DATACENTERS_V4.len(), 5);
        assert_eq!(TG_DATACENTERS_V6.len(), 5);
    }

    #[test]
    fn secure_padding_never_produces_aligned_total() {
        let rng = SecureRandom::new();
        for data_len in 0..1000 {
            for _ in 0..100 {
                let padding = secure_padding_len(data_len, &rng);
                assert!(
                    padding <= 3,
                    "padding out of range: data_len={data_len}, padding={padding}"
                );
                assert_ne!(
                    (data_len + padding) % 4,
                    0,
                    "invariant violated: data_len={data_len}, padding={padding}, total={}",
                    data_len + padding
                );
            }
        }
    }
}
