use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(unix)]
use nix::dir::Dir;
#[cfg(unix)]
use nix::fcntl::{OFlag, openat};
#[cfg(unix)]
use nix::sys::stat::Mode;

use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use super::*;
#[cfg(unix)]
use crate::util::secure_fs::open_dir_nofollow;

// Path-based static snapshot fallback for platforms without directory descriptors.
#[cfg(not(unix))]
mod static_site_fallback;

const WEB_CAPABILITY_CONTEXT_V1: &[u8] = b"tdesktop-web-proxy-bridge-v1\n";
const WEB_CAPABILITY_CONTEXT_V2: &[u8] = b"tdesktop-web-proxy-bridge-v2\n";
const WEB_DEBUG_FINGERPRINT_CONTEXT: &[u8] = b"telemt-web-debug-key-fingerprint-v1\0";
const MAX_WEB_STATIC_DEPTH: usize = 64;

// Exact bindings and wildcard templates share one immutable snapshot builder.
mod build;
pub(super) use build::rebuild;
// Cold wildcard derivation uses the existing immutable authentication snapshot.
mod wildcard;

fn debug_key_fingerprint(secret: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(WEB_DEBUG_FINGERPRINT_CONTEXT);
    digest.update(secret);
    hex::encode(&digest.finalize()[..8])
}

/// Derives the Telegram Desktop WEB capability for one exact secret, host, and base path.
pub(crate) fn derive_web_capability(
    secret: &[u8],
    host: &[u8],
    base_path: &[u8],
) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret)
        .map_err(|_| ProxyError::Config("WEB capability secret must not be empty".to_string()))?;
    if base_path.is_empty() {
        mac.update(WEB_CAPABILITY_CONTEXT_V1);
        mac.update(host);
    } else {
        mac.update(WEB_CAPABILITY_CONTEXT_V2);
        mac.update(host);
        mac.update(b"\n");
        mac.update(base_path);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn client_secret(secret: [u8; 16], mode: WebSecretMode) -> ([u8; 17], usize) {
    let mut client_secret = [0u8; 17];
    match mode {
        WebSecretMode::Plain => {
            client_secret[..16].copy_from_slice(&secret);
            (client_secret, 16)
        }
        WebSecretMode::Dd => {
            client_secret[0] = 0xdd;
            client_secret[1..].copy_from_slice(&secret);
            (client_secret, 17)
        }
    }
}

fn build_decoy(
    config: &ProxyConfig,
    vhost_idx: usize,
    vhost: &WebVhostConfig,
    limits: &WebLimitsConfig,
    static_files: &mut usize,
    static_bytes: &mut usize,
) -> Result<WebRuntimeDecoy> {
    match &vhost.decoy {
        WebDecoyConfig::HttpUpstream { upstream, resolve } => {
            decoy_dns::build_upstream(config, vhost_idx, upstream, *resolve)
        }
        WebDecoyConfig::StaticDirectory { directory, index } => {
            let site = load_static_site(directory, index, limits, static_files, static_bytes)?;
            Ok(WebRuntimeDecoy::StaticDirectory(Arc::new(site)))
        }
    }
}

fn load_static_site(
    root: &Path,
    index: &str,
    limits: &WebLimitsConfig,
    total_files: &mut usize,
    total_bytes: &mut usize,
) -> Result<WebStaticSite> {
    let mut assets = BTreeMap::new();
    #[cfg(unix)]
    {
        let directory = open_static_root(root)?;
        load_static_directory(
            directory,
            Path::new(""),
            root,
            &mut assets,
            total_files,
            total_bytes,
            limits,
            0,
        )?;
    }
    #[cfg(not(unix))]
    {
        static_site_fallback::load_static_site_by_path(
            root,
            limits,
            &mut assets,
            total_files,
            total_bytes,
        )?;
    }
    if !assets.contains_key(&format!("/{index}")) {
        return Err(ProxyError::Config(format!(
            "WEB static directory `{}` does not contain index `{index}`",
            root.display()
        )));
    }
    Ok(WebStaticSite {
        assets,
        index: index.to_string(),
    })
}

#[cfg(unix)]
fn open_static_root(root: &Path) -> Result<Dir> {
    let descriptor = open_dir_nofollow(root).map_err(|error| {
        ProxyError::Config(format!(
            "WEB static directory `{}` must be a real directory, not a symlink: {error}",
            root.display()
        ))
    })?;
    Dir::from_fd(descriptor).map_err(|error| {
        ProxyError::Config(format!(
            "failed to read WEB static directory `{}`: {error}",
            root.display()
        ))
    })
}

#[cfg(unix)]
fn load_static_directory(
    mut directory: Dir,
    relative: &Path,
    root: &Path,
    assets: &mut BTreeMap<String, WebStaticAsset>,
    total_files: &mut usize,
    total_bytes: &mut usize,
    limits: &WebLimitsConfig,
    depth: usize,
) -> Result<()> {
    let mut entries = Vec::new();
    for entry in directory.iter() {
        let entry = entry.map_err(|error| {
            ProxyError::Config(format!(
                "failed to read WEB static directory `{}`: {error}",
                root.join(relative).display()
            ))
        })?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if *total_files >= limits.max_static_files {
            return Err(ProxyError::Config(
                "WEB static entries exceed process-wide web.limits.max_static_files".to_string(),
            ));
        }
        *total_files += 1;
        entries.push(OsString::from_vec(name.to_vec()));
    }
    entries.sort_unstable();

    for name in entries {
        let relative_path = relative.join(&name);
        let display_path = root.join(&relative_path);
        let descriptor = openat(
            &directory,
            name.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| {
            ProxyError::Config(format!(
                "failed to open WEB static entry `{}` without following symlinks: {error}",
                display_path.display()
            ))
        })?;
        let file = fs::File::from(descriptor);
        let metadata = file.metadata().map_err(|error| {
            ProxyError::Config(format!(
                "failed to inspect WEB static entry `{}`: {error}",
                display_path.display()
            ))
        })?;
        if metadata.is_dir() {
            if depth >= MAX_WEB_STATIC_DEPTH {
                return Err(ProxyError::Config(format!(
                    "WEB static directory `{}` exceeds the maximum nesting depth",
                    display_path.display()
                )));
            }
            let descriptor = file.into();
            let child = Dir::from_fd(descriptor).map_err(|error| {
                ProxyError::Config(format!(
                    "failed to open WEB static directory `{}`: {error}",
                    display_path.display()
                ))
            })?;
            load_static_directory(
                child,
                &relative_path,
                root,
                assets,
                total_files,
                total_bytes,
                limits,
                depth + 1,
            )?;
            continue;
        }
        if !metadata.is_file() {
            return Err(ProxyError::Config(format!(
                "WEB static entry `{}` must be a regular file",
                display_path.display()
            )));
        }
        load_static_file(
            file,
            &metadata,
            &relative_path,
            &display_path,
            assets,
            total_bytes,
            limits,
        )?;
    }
    Ok(())
}

fn load_static_file(
    mut file: fs::File,
    metadata: &fs::Metadata,
    relative: &Path,
    display_path: &Path,
    assets: &mut BTreeMap<String, WebStaticAsset>,
    total_bytes: &mut usize,
    limits: &WebLimitsConfig,
) -> Result<()> {
    let file_len = usize::try_from(metadata.len()).map_err(|_| {
        ProxyError::Config(format!(
            "WEB static file `{}` is too large",
            display_path.display()
        ))
    })?;
    if file_len > limits.max_static_file_bytes {
        return Err(ProxyError::Config(format!(
            "WEB static file `{}` exceeds web.limits.max_static_file_bytes",
            display_path.display()
        )));
    }
    *total_bytes = total_bytes.checked_add(file_len).ok_or_else(|| {
        ProxyError::Config("WEB static snapshot byte count overflowed usize".to_string())
    })?;
    if *total_bytes > limits.max_static_bytes {
        return Err(ProxyError::Config(
            "WEB static snapshots exceed process-wide web.limits.max_static_bytes".to_string(),
        ));
    }
    let route = static_route(relative)?;
    let mut body = Vec::with_capacity(file_len);
    file.by_ref()
        .take(limits.max_static_file_bytes as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|error| {
            ProxyError::Config(format!(
                "failed to read WEB static file `{}`: {error}",
                display_path.display()
            ))
        })?;
    let final_metadata = file.metadata().map_err(|error| {
        ProxyError::Config(format!(
            "failed to recheck WEB static file `{}`: {error}",
            display_path.display()
        ))
    })?;
    if body.len() != file_len || !static_file_version_matches(metadata, &final_metadata) {
        return Err(ProxyError::Config(format!(
            "WEB static file `{}` changed while its snapshot was built",
            display_path.display()
        )));
    }
    let etag = format!("\"{}\"", hex::encode(Sha256::digest(&body)));
    assets.insert(
        route,
        WebStaticAsset {
            body: Bytes::from(body),
            content_type: static_content_type(relative),
            etag,
        },
    );
    Ok(())
}

#[cfg(unix)]
fn static_file_version_matches(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn static_file_version_matches(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.created().ok() == after.created().ok()
}

fn static_route(relative: &Path) -> Result<String> {
    let mut route = String::new();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(ProxyError::Config(
                "WEB static path contains an unsafe component".to_string(),
            ));
        };
        let component = component.to_str().ok_or_else(|| {
            ProxyError::Config("WEB static file names must be valid UTF-8".to_string())
        })?;
        route.push('/');
        route.push_str(component);
    }
    Ok(route)
}

fn static_content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

// Runtime WEB construction tests remain separate from the production loader.
#[cfg(test)]
#[path = "runtime_web/tests.rs"]
mod tests;
