use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(unix)]
use nix::fcntl::{Flock, FlockArg, OFlag, openat, renameat};
#[cfg(unix)]
use nix::sys::stat::Mode;
#[cfg(unix)]
use nix::unistd::{UnlinkatFlags, fsync, unlinkat};
#[cfg(unix)]
use tracing::warn;

use super::compute_source_revision;
use crate::api::model::ApiFailure;
use crate::config::ProxyConfig;
#[cfg(unix)]
use crate::util::secure_fs::AnchoredPath;

const MAX_CONFIG_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

enum AtomicWriteError {
    Conflict,
    ReadGraph(String),
    Io(std::io::Error),
    RuntimeConflict,
}

pub(in crate::api) type CommitCheck = Arc<dyn Fn() -> bool + Send + Sync>;

#[derive(Debug)]
struct RuntimeConflict;
impl std::fmt::Display for RuntimeConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Runtime configuration changed before persistence")
    }
}
impl std::error::Error for RuntimeConflict {}

struct ExistingTarget {
    contents: String,
    metadata: std::fs::Metadata,
}

struct GraphFence<'a> {
    config_path: &'a Path,
    expected_revision: &'a str,
    runtime_check: Option<&'a CommitCheck>,
}

struct ConfigWriteLock {
    #[cfg(unix)]
    _file: Flock<File>,
}

impl ConfigWriteLock {
    fn acquire(path: &Path) -> std::io::Result<Self> {
        let path = normalize_path(path);
        #[cfg(unix)]
        {
            let lock_path = sibling_lock_path(&path);
            let anchored = AnchoredPath::open_creating_parents(&lock_path, 0o750)?;
            let descriptor = openat(
                anchored.parent(),
                anchored.name(),
                OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::from_bits_truncate(0o600),
            )
            .map_err(errno_to_io)?;
            let file = File::from(descriptor);
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "config lock must be a regular file with one directory entry",
                ));
            }
            let file = Flock::lock(file, FlockArg::LockExclusive)
                .map_err(|(_, error)| errno_to_io(error))?;
            Ok(Self { _file: file })
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(Self {})
        }
    }
}

/// Replaces one config source through a same-directory rename after syncing file data.
pub(in crate::api) async fn write_atomic(
    path: PathBuf,
    contents: String,
) -> Result<(), ApiFailure> {
    tokio::task::spawn_blocking(move || {
        let _lock = ConfigWriteLock::acquire(&path)?;
        write_atomic_sync(&path, None, &contents, None).map(|_| ())
    })
    .await
    .map_err(|error| ApiFailure::internal(format!("failed to join writer: {error}")))?
    .map_err(|error| ApiFailure::internal(format!("failed to write config: {error}")))
}

/// Replaces one source only if both its graph revision and owner contents are unchanged.
pub(in crate::api) async fn write_atomic_if_unchanged(
    config_path: PathBuf,
    expected_revision: String,
    path: PathBuf,
    expected_contents: String,
    contents: String,
) -> Result<String, ApiFailure> {
    write_atomic_with_runtime_check(
        config_path,
        expected_revision,
        path,
        expected_contents,
        contents,
        None,
    )
    .await
}

/// The runtime check runs after source fencing, immediately before the rename.
/// It is an optimistic check, not a lock against later runtime publication.
pub(in crate::api) async fn write_atomic_with_runtime_check(
    config_path: PathBuf,
    expected_revision: String,
    path: PathBuf,
    expected_contents: String,
    contents: String,
    runtime_check: Option<CommitCheck>,
) -> Result<String, ApiFailure> {
    tokio::task::spawn_blocking(move || {
        let config_path = normalize_path(&config_path);
        let path = normalize_path(&path);
        // Every API mutation locks the root source so writes to different includes serialize.
        let _lock = ConfigWriteLock::acquire(&config_path).map_err(AtomicWriteError::Io)?;
        let graph = ProxyConfig::read_source_graph(&config_path)
            .map_err(|error| AtomicWriteError::ReadGraph(error.to_string()))?;
        if compute_source_revision(&graph) != expected_revision {
            return Err(AtomicWriteError::Conflict);
        }
        write_atomic_sync(
            &path,
            Some(&expected_contents),
            &contents,
            Some(GraphFence {
                config_path: &config_path,
                expected_revision: &expected_revision,
                runtime_check: runtime_check.as_ref(),
            }),
        )
        .map_err(|error| {
            if error
                .get_ref()
                .is_some_and(|inner| inner.is::<RuntimeConflict>())
            {
                AtomicWriteError::RuntimeConflict
            } else if error.kind() == std::io::ErrorKind::AlreadyExists {
                AtomicWriteError::Conflict
            } else {
                AtomicWriteError::Io(error)
            }
        })?
        .ok_or_else(|| {
            AtomicWriteError::Io(std::io::Error::other(
                "config graph fence did not produce a committed revision",
            ))
        })
    })
    .await
    .map_err(|error| ApiFailure::internal(format!("failed to join writer: {error}")))?
    .map_err(|error| match error {
        AtomicWriteError::Conflict => revision_conflict(),
        AtomicWriteError::RuntimeConflict => ApiFailure::new(
            hyper::StatusCode::CONFLICT,
            "runtime_conflict",
            "Runtime configuration changed before persistence",
        ),
        AtomicWriteError::ReadGraph(error) => {
            ApiFailure::internal(format!("failed to verify config graph: {error}"))
        }
        AtomicWriteError::Io(error) => {
            ApiFailure::internal(format!("failed to write config: {error}"))
        }
    })
}

fn revision_conflict() -> ApiFailure {
    ApiFailure::new(
        hyper::StatusCode::CONFLICT,
        "revision_conflict",
        "Config revision changed before persistence",
    )
}

fn sibling_lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("config.toml"))
        .to_os_string();
    name.push(".lock");
    path.parent().unwrap_or_else(|| Path::new(".")).join(name)
}

fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|current| current.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

fn fenced_post_commit_revision(
    fence: GraphFence<'_>,
    path: &Path,
    contents: &str,
) -> std::io::Result<String> {
    let mut graph = ProxyConfig::read_source_graph(fence.config_path)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    if compute_source_revision(&graph) != fence.expected_revision {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "config graph changed during persistence",
        ));
    }
    let path = normalize_path(path);
    let Some(owner) = graph.source_contents.get_mut(&path) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config source owner left the source graph during persistence",
        ));
    };
    *owner = contents.to_string();
    let revision = compute_source_revision(&graph);
    if fence.runtime_check.is_some_and(|check| !check()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            RuntimeConflict,
        ));
    }
    Ok(revision)
}

#[cfg(unix)]
fn open_existing_target(anchored: &AnchoredPath) -> std::io::Result<Option<ExistingTarget>> {
    let descriptor = match openat(
        anchored.parent(),
        anchored.name(),
        OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(errno_to_io(error)),
    };
    let mut file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.len() > MAX_CONFIG_SOURCE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config target must be a bounded regular file with one directory entry",
        ));
    }
    let mut contents = String::with_capacity(metadata.len() as usize);
    Read::take(&mut file, MAX_CONFIG_SOURCE_BYTES + 1).read_to_string(&mut contents)?;
    if contents.len() as u64 > MAX_CONFIG_SOURCE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "config target exceeds the source size limit",
        ));
    }
    let completed = file.metadata()?;
    if !same_target(&metadata, &completed) || metadata.len() != completed.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "config target changed while it was read",
        ));
    }
    Ok(Some(ExistingTarget { contents, metadata }))
}

#[cfg(not(unix))]
fn open_existing_target(path: &Path) -> std::io::Result<Option<ExistingTarget>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_SOURCE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "config target must be a bounded regular file",
        ));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(Some(ExistingTarget { contents, metadata }))
}

fn same_target(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        left.len() == right.len() && left.modified().ok() == right.modified().ok()
    }
}

#[cfg(unix)]
fn write_atomic_sync(
    path: &Path,
    expected_contents: Option<&str>,
    contents: &str,
    graph_fence: Option<GraphFence<'_>>,
) -> std::io::Result<Option<String>> {
    let anchored = AnchoredPath::open_creating_parents(path, 0o750)?;
    let existing = open_existing_target(&anchored)?;
    validate_expected_contents(existing.as_ref(), expected_contents)?;
    let temp_name = format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("config.toml"),
        rand::random::<u64>()
    );
    let descriptor = openat(
        anchored.parent(),
        temp_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(errno_to_io)?;
    let write_result = write_and_publish(
        descriptor,
        path,
        &anchored,
        &temp_name,
        existing.as_ref(),
        contents,
        graph_fence,
    );
    if write_result.is_err() {
        let _ = unlinkat(
            anchored.parent(),
            temp_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
    }
    write_result
}

#[cfg(unix)]
fn write_and_publish(
    descriptor: std::os::fd::OwnedFd,
    path: &Path,
    anchored: &AnchoredPath,
    temp_name: &str,
    existing: Option<&ExistingTarget>,
    contents: &str,
    graph_fence: Option<GraphFence<'_>>,
) -> std::io::Result<Option<String>> {
    let mut file = File::from(descriptor);
    if let Some(existing) = existing {
        use nix::unistd::{Gid, Uid, fchown};

        fchown(
            &file,
            Some(Uid::from_raw(existing.metadata.uid())),
            Some(Gid::from_raw(existing.metadata.gid())),
        )
        .map_err(errno_to_io)?;
        file.set_permissions(std::fs::Permissions::from_mode(
            existing.metadata.mode() & 0o7777,
        ))?;
    }
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    let current = open_existing_target(anchored)?;
    if !target_unchanged(existing, current.as_ref()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "config target changed during persistence",
        ));
    }
    let committed_revision = graph_fence
        .map(|fence| fenced_post_commit_revision(fence, path, contents))
        .transpose()?;
    renameat(
        anchored.parent(),
        temp_name,
        anchored.parent(),
        anchored.name(),
    )
    .map_err(errno_to_io)?;
    // Rename is the commit boundary. A later directory-sync error cannot be reported as an
    // uncommitted mutation because mandatory in-process publication must still run.
    if let Err(error) = fsync(anchored.parent()).map_err(errno_to_io) {
        warn!(
            path = %path.display(),
            %error,
            "Config rename committed but directory durability sync failed"
        );
    }
    Ok(committed_revision)
}

#[cfg(not(unix))]
fn write_atomic_sync(
    path: &Path,
    expected_contents: Option<&str>,
    contents: &str,
    graph_fence: Option<GraphFence<'_>>,
) -> std::io::Result<Option<String>> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let existing = open_existing_target(path)?;
    validate_expected_contents(existing.as_ref(), expected_contents)?;
    let temp = parent.join(format!(".telemt.tmp-{}", rand::random::<u64>()));
    std::fs::write(&temp, contents)?;
    let current = open_existing_target(path)?;
    if !target_unchanged(existing.as_ref(), current.as_ref()) {
        let _ = std::fs::remove_file(&temp);
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "config target changed during persistence",
        ));
    }
    let committed_revision = match graph_fence
        .map(|fence| fenced_post_commit_revision(fence, path, contents))
        .transpose()
    {
        Ok(revision) => revision,
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            return Err(error);
        }
    };
    std::fs::rename(temp, path)?;
    Ok(committed_revision)
}

fn validate_expected_contents(
    existing: Option<&ExistingTarget>,
    expected_contents: Option<&str>,
) -> std::io::Result<()> {
    if expected_contents
        .is_some_and(|expected| existing.is_none_or(|target| target.contents != expected))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "config source changed before persistence",
        ));
    }
    Ok(())
}

fn target_unchanged(existing: Option<&ExistingTarget>, current: Option<&ExistingTarget>) -> bool {
    match (existing, current) {
        (Some(expected), Some(current)) => {
            same_target(&expected.metadata, &current.metadata)
                && expected.contents == current.contents
        }
        (None, None) => true,
        _ => false,
    }
}

#[cfg(unix)]
fn errno_to_io(error: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(error as i32)
}
