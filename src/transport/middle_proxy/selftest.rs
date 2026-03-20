use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BndAddrStatus {
    Ok,
    Bogon,
    Error,
}

impl BndAddrStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Bogon => "bogon",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BndPortStatus {
    Ok,
    Zero,
    Error,
}

impl BndPortStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Zero => "zero",
            Self::Error => "error",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MeBndSnapshot {
    pub addr_status: &'static str,
    pub port_status: &'static str,
    pub last_addr: Option<SocketAddr>,
    pub last_seen_age_secs: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct MeUpstreamBndSnapshot {
    pub upstream_id: usize,
    pub addr_status: &'static str,
    pub port_status: &'static str,
    pub last_addr: Option<SocketAddr>,
    pub last_ip: Option<IpAddr>,
    pub last_seen_age_secs: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct MeTimeskewSnapshot {
    pub max_skew_secs_15m: Option<u64>,
    pub samples_15m: usize,
    pub last_skew_secs: Option<u64>,
    pub last_source: Option<&'static str>,
    pub last_seen_age_secs: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
struct MeTimeskewSample {
    ts_epoch_secs: u64,
    skew_secs: u64,
    source: &'static str,
}

#[derive(Debug)]
struct MeSelftestState {
    bnd_addr_status: BndAddrStatus,
    bnd_port_status: BndPortStatus,
    bnd_last_addr: Option<SocketAddr>,
    bnd_last_seen_epoch_secs: Option<u64>,
    upstream_bnd: HashMap<usize, UpstreamBndState>,
    timeskew_samples: VecDeque<MeTimeskewSample>,
}

#[derive(Clone, Copy, Debug)]
struct UpstreamBndState {
    addr_status: BndAddrStatus,
    port_status: BndPortStatus,
    last_addr: Option<SocketAddr>,
    last_ip: Option<IpAddr>,
    last_seen_epoch_secs: Option<u64>,
}

impl Default for MeSelftestState {
    fn default() -> Self {
        Self {
            bnd_addr_status: BndAddrStatus::Error,
            bnd_port_status: BndPortStatus::Error,
            bnd_last_addr: None,
            bnd_last_seen_epoch_secs: None,
            upstream_bnd: HashMap::new(),
            timeskew_samples: VecDeque::new(),
        }
    }
}

const MAX_TIMESKEW_SAMPLES: usize = 512;
const TIMESKEW_WINDOW_SECS: u64 = 15 * 60;

static ME_SELFTEST_STATE: OnceLock<Mutex<MeSelftestState>> = OnceLock::new();

fn state() -> &'static Mutex<MeSelftestState> {
    ME_SELFTEST_STATE.get_or_init(|| Mutex::new(MeSelftestState::default()))
}

pub(crate) fn record_bnd_status(
    addr_status: BndAddrStatus,
    port_status: BndPortStatus,
    last_addr: Option<SocketAddr>,
) {
    let now_epoch_secs = now_epoch_secs();
    let Ok(mut guard) = state().lock() else {
        return;
    };
    guard.bnd_addr_status = addr_status;
    guard.bnd_port_status = port_status;
    guard.bnd_last_addr = last_addr;
    guard.bnd_last_seen_epoch_secs = Some(now_epoch_secs);
}

pub(crate) fn bnd_snapshot() -> MeBndSnapshot {
    let now_epoch_secs = now_epoch_secs();
    let Ok(guard) = state().lock() else {
        return MeBndSnapshot {
            addr_status: BndAddrStatus::Error.as_str(),
            port_status: BndPortStatus::Error.as_str(),
            last_addr: None,
            last_seen_age_secs: None,
        };
    };
    MeBndSnapshot {
        addr_status: guard.bnd_addr_status.as_str(),
        port_status: guard.bnd_port_status.as_str(),
        last_addr: guard.bnd_last_addr,
        last_seen_age_secs: guard
            .bnd_last_seen_epoch_secs
            .map(|value| now_epoch_secs.saturating_sub(value)),
    }
}

pub(crate) fn record_upstream_bnd_status(
    upstream_id: usize,
    addr_status: BndAddrStatus,
    port_status: BndPortStatus,
    last_addr: Option<SocketAddr>,
    last_ip: Option<IpAddr>,
) {
    let now_epoch_secs = now_epoch_secs();
    let Ok(mut guard) = state().lock() else {
        return;
    };
    guard.upstream_bnd.insert(
        upstream_id,
        UpstreamBndState {
            addr_status,
            port_status,
            last_addr,
            last_ip,
            last_seen_epoch_secs: Some(now_epoch_secs),
        },
    );
}

pub(crate) fn upstream_bnd_snapshots() -> Vec<MeUpstreamBndSnapshot> {
    let now_epoch_secs = now_epoch_secs();
    let Ok(guard) = state().lock() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(guard.upstream_bnd.len());
    for (upstream_id, entry) in &guard.upstream_bnd {
        out.push(MeUpstreamBndSnapshot {
            upstream_id: *upstream_id,
            addr_status: entry.addr_status.as_str(),
            port_status: entry.port_status.as_str(),
            last_addr: entry.last_addr,
            last_ip: entry.last_ip,
            last_seen_age_secs: entry
                .last_seen_epoch_secs
                .map(|value| now_epoch_secs.saturating_sub(value)),
        });
    }
    out.sort_by_key(|entry| entry.upstream_id);
    out
}

pub(crate) fn record_timeskew_sample(source: &'static str, skew_secs: u64) {
    let now_epoch_secs = now_epoch_secs();
    let Ok(mut guard) = state().lock() else {
        return;
    };
    guard.timeskew_samples.push_back(MeTimeskewSample {
        ts_epoch_secs: now_epoch_secs,
        skew_secs,
        source,
    });
    while guard.timeskew_samples.len() > MAX_TIMESKEW_SAMPLES {
        guard.timeskew_samples.pop_front();
    }
    let cutoff = now_epoch_secs.saturating_sub(TIMESKEW_WINDOW_SECS * 2);
    while guard
        .timeskew_samples
        .front()
        .is_some_and(|sample| sample.ts_epoch_secs < cutoff)
    {
        guard.timeskew_samples.pop_front();
    }
}

pub(crate) fn timeskew_snapshot() -> MeTimeskewSnapshot {
    let now_epoch_secs = now_epoch_secs();
    let Ok(guard) = state().lock() else {
        return MeTimeskewSnapshot::default();
    };

    let mut max_skew_secs_15m = None;
    let mut samples_15m = 0usize;
    let window_start = now_epoch_secs.saturating_sub(TIMESKEW_WINDOW_SECS);
    for sample in &guard.timeskew_samples {
        if sample.ts_epoch_secs < window_start {
            continue;
        }
        samples_15m = samples_15m.saturating_add(1);
        max_skew_secs_15m = Some(max_skew_secs_15m.unwrap_or(0).max(sample.skew_secs));
    }

    let (last_skew_secs, last_source, last_seen_age_secs) =
        if let Some(last) = guard.timeskew_samples.back() {
            (
                Some(last.skew_secs),
                Some(last.source),
                Some(now_epoch_secs.saturating_sub(last.ts_epoch_secs)),
            )
        } else {
            (None, None, None)
        };

    MeTimeskewSnapshot {
        max_skew_secs_15m,
        samples_15m,
        last_skew_secs,
        last_source,
        last_seen_age_secs,
    }
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
