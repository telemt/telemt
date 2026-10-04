use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read, Write};
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg, OFlag, openat};
use nix::sys::stat::Mode;
use nix::unistd::{Pid, UnlinkatFlags, getpid, unlinkat};
use tracing::{debug, info, warn};

use super::DaemonError;
use crate::util::secure_fs::AnchoredPath;

/// PID file manager backed by a persistent sibling lock file.
pub struct PidFile {
    path: PathBuf,
    strict_runtime_paths: bool,
    lock_path: PathBuf,
    pid_file: Option<File>,
    pid_identity: Option<FileIdentity>,
    lock_file: Option<Flock<File>>,
    anchor: Option<AnchoredPath>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

impl PidFile {
    /// Creates a PID manager with explicit parent-path policy; `false` allows legacy parents.
    pub fn new<P: AsRef<Path>>(path: P, strict_runtime_paths: bool) -> Self {
        let path = normalize_pid_path(path.as_ref());
        let lock_path = sibling_lock_path(&path);
        Self {
            path,
            strict_runtime_paths,
            lock_path,
            pid_file: None,
            pid_identity: None,
            lock_file: None,
            anchor: None,
        }
    }

    /// Checks whether the PID file names a running process without modifying either file.
    pub fn check_running(&self) -> Result<Option<i32>, DaemonError> {
        let Some(pid) = read_pid_file_if_exists(&self.path, self.strict_runtime_paths)? else {
            return Ok(None);
        };
        Ok(is_process_running(pid).then_some(pid))
    }

    /// Acquires the persistent sibling lock and writes the current PID.
    ///
    /// Fails if another owner holds the lock or the existing PID names a running process.
    pub fn acquire(&mut self) -> Result<(), DaemonError> {
        let anchor =
            AnchoredPath::open_runtime_parent(&self.path, Some(0o755), self.strict_runtime_paths)
                .map_err(|error| {
                DaemonError::PidFile(format!(
                    "cannot open PID parent for {}: {}",
                    self.path.display(),
                    error
                ))
            })?;
        let lock_name = self.lock_path.file_name().ok_or_else(|| {
            DaemonError::PidFile(format!(
                "lock path {} has no file name",
                self.lock_path.display()
            ))
        })?;
        let lock_file = open_file_at(
            &anchor,
            lock_name,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            0o644,
        )
        .map_err(|error| {
            DaemonError::PidFile(format!(
                "cannot open lock file {}: {}",
                self.lock_path.display(),
                error
            ))
        })?;
        validate_regular_single_link(&lock_file, &self.lock_path)?;
        let lock_file =
            Flock::lock(lock_file, FlockArg::LockExclusiveNonblock).map_err(|(_, errno)| {
                if let Some(pid) = read_pid_file_at(&anchor, &self.path)
                    .ok()
                    .flatten()
                    .filter(|pid| is_process_running(*pid))
                {
                    DaemonError::AlreadyRunning(pid)
                } else {
                    DaemonError::PidFile(format!(
                        "cannot lock {}: {}",
                        self.lock_path.display(),
                        errno
                    ))
                }
            })?;

        if let Some(pid) = read_pid_file_at(&anchor, &self.path)?
            && is_process_running(pid)
        {
            return Err(DaemonError::AlreadyRunning(pid));
        }

        let mut pid_file = open_file_at(
            &anchor,
            anchor.name(),
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
            0o644,
        )
        .map_err(|error| {
            DaemonError::PidFile(format!("cannot open {}: {}", self.path.display(), error))
        })?;
        let pid_metadata = validate_regular_single_link(&pid_file, &self.path)?;
        let pid_identity = FileIdentity::from_metadata(&pid_metadata);
        // Validate the opened inode before modifying it so a hard-link substitution
        // cannot turn PID publication into truncation of an unrelated file.
        pid_file.set_len(0).map_err(|error| {
            DaemonError::PidFile(format!(
                "cannot truncate {}: {}",
                self.path.display(),
                error
            ))
        })?;
        let pid = getpid();
        writeln!(pid_file, "{}", pid).map_err(|error| {
            DaemonError::PidFile(format!(
                "cannot write PID to {}: {}",
                self.path.display(),
                error
            ))
        })?;
        pid_file.sync_data().map_err(|error| {
            DaemonError::PidFile(format!(
                "cannot sync PID file {}: {}",
                self.path.display(),
                error
            ))
        })?;

        self.pid_file = Some(pid_file);
        self.pid_identity = Some(pid_identity);
        self.lock_file = Some(lock_file);
        self.anchor = Some(anchor);
        info!(pid = pid.as_raw(), path = %self.path.display(), "PID file created");
        Ok(())
    }

    /// Removes the PID file while retaining exclusive lock ownership until cleanup completes.
    pub fn release(&mut self) -> Result<(), DaemonError> {
        if self.lock_file.is_none() {
            self.pid_file = None;
            self.pid_identity = None;
            self.anchor = None;
            return Ok(());
        }

        let removal = match self.anchor.as_ref() {
            Some(anchor) => remove_owned_pid_file(anchor, &self.path, self.pid_identity),
            None => Err(DaemonError::PidFile(
                "PID file lock is held without a directory anchor".to_string(),
            )),
        };
        self.pid_file = None;
        self.pid_identity = None;
        self.lock_file = None;
        self.anchor = None;
        removal?;
        debug!(path = %self.path.display(), "PID file removed");
        Ok(())
    }

    /// Returns the path to this PID file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns open files whose ownership must follow the target runtime identity.
    pub(super) fn ownership_file_handles(&self) -> [Option<&File>; 2] {
        [self.pid_file.as_ref(), self.lock_file.as_deref()]
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        if self.lock_file.is_some()
            && let Err(error) = self.release()
        {
            warn!(error = %error, "Failed to clean up PID file on drop");
        }
    }
}

fn sibling_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    lock_path.into()
}

fn normalize_pid_path(path: &Path) -> PathBuf {
    let legacy_run = Path::new("/var/run");
    let Ok(remainder) = path.strip_prefix(legacy_run) else {
        return path.to_path_buf();
    };
    let Ok(var_metadata) = fs::metadata("/var") else {
        return path.to_path_buf();
    };
    let Ok(link_metadata) = fs::symlink_metadata(legacy_run) else {
        return path.to_path_buf();
    };
    let Ok(target) = fs::read_link(legacy_run) else {
        return path.to_path_buf();
    };
    let trusted_var = var_metadata.is_dir()
        && var_metadata.uid() == 0
        && var_metadata.permissions().mode() & 0o022 == 0;
    let trusted_alias = link_metadata.file_type().is_symlink()
        && link_metadata.uid() == 0
        && (target == Path::new("/run") || target == Path::new("../run"));
    if trusted_var && trusted_alias {
        Path::new("/run").join(remainder)
    } else {
        path.to_path_buf()
    }
}

fn open_file_at(anchor: &AnchoredPath, name: &OsStr, flags: OFlag, mode: u32) -> io::Result<File> {
    let descriptor = openat(
        anchor.parent(),
        name,
        flags,
        Mode::from_bits_truncate(mode as libc::mode_t),
    )
    .map_err(|error| io::Error::from_raw_os_error(error as i32))?;
    Ok(File::from(descriptor))
}

fn read_pid_file_if_exists(
    path: &Path,
    strict_runtime_paths: bool,
) -> Result<Option<i32>, DaemonError> {
    let anchor = match AnchoredPath::open_runtime_parent(path, None, strict_runtime_paths) {
        Ok(anchor) => anchor,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(DaemonError::PidFile(format!(
                "cannot open PID parent for {}: {}",
                path.display(),
                error
            )));
        }
    };
    read_pid_file_at(&anchor, path)
}

fn read_pid_file_at(anchor: &AnchoredPath, path: &Path) -> Result<Option<i32>, DaemonError> {
    let mut file = match open_file_at(
        anchor,
        anchor.name(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(DaemonError::PidFile(format!(
                "cannot read {}: {}",
                path.display(),
                error
            )));
        }
    };
    let metadata = validate_regular_single_link(&file, path)?;
    if metadata.len() > 64 {
        return Err(DaemonError::PidFile(format!(
            "invalid PID in {}",
            path.display()
        )));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents).map_err(|error| {
        DaemonError::PidFile(format!("cannot read {}: {}", path.display(), error))
    })?;
    let pid: i32 = contents
        .trim()
        .parse()
        .map_err(|_| DaemonError::PidFile(format!("invalid PID in {}", path.display())))?;
    if pid <= 1 {
        return Err(DaemonError::PidFile(format!(
            "invalid PID in {}",
            path.display()
        )));
    }
    Ok(Some(pid))
}

fn remove_owned_pid_file(
    anchor: &AnchoredPath,
    path: &Path,
    expected: Option<FileIdentity>,
) -> Result<(), DaemonError> {
    let file = match open_file_at(
        anchor,
        anchor.name(),
        OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(DaemonError::PidFile(format!(
                "cannot inspect {} before removal: {}",
                path.display(),
                error
            )));
        }
    };
    let metadata = validate_regular_single_link(&file, path)?;
    if expected != Some(FileIdentity::from_metadata(&metadata)) {
        return Err(DaemonError::PidFile(format!(
            "refusing to remove replaced PID file {}",
            path.display()
        )));
    }
    drop(file);
    unlinkat(anchor.parent(), anchor.name(), UnlinkatFlags::NoRemoveDir).map_err(|error| {
        DaemonError::PidFile(format!(
            "cannot remove {}: {}",
            path.display(),
            io::Error::from_raw_os_error(error as i32)
        ))
    })
}

fn validate_regular_single_link(file: &File, path: &Path) -> Result<fs::Metadata, DaemonError> {
    let metadata = file.metadata().map_err(|error| {
        DaemonError::PidFile(format!("cannot inspect {}: {}", path.display(), error))
    })?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(DaemonError::PidFile(format!(
            "{} must be a regular file with one directory entry",
            path.display()
        )));
    }
    Ok(metadata)
}

/// Reads a PID using the selected parent-path policy; `false` allows legacy parents.
#[allow(dead_code)]
pub fn read_pid_file<P: AsRef<Path>>(
    path: P,
    strict_runtime_paths: bool,
) -> Result<i32, DaemonError> {
    let path = normalize_pid_path(path.as_ref());
    read_pid_file_if_exists(&path, strict_runtime_paths)?.ok_or_else(|| {
        DaemonError::PidFile(format!(
            "cannot read {}: file does not exist",
            path.display()
        ))
    })
}

/// Signals a lock-owning process using the same parent-path policy for PID and lock files.
#[allow(dead_code)]
pub fn signal_pid_file<P: AsRef<Path>>(
    path: P,
    signal: nix::sys::signal::Signal,
    strict_runtime_paths: bool,
) -> Result<(), DaemonError> {
    let path = normalize_pid_path(path.as_ref());
    let pid = read_pid_file(&path, strict_runtime_paths)?;
    #[cfg(target_os = "linux")]
    let pidfd = open_pidfd(pid)?;
    if !daemon_lock_is_held(&path, strict_runtime_paths)? {
        return Err(DaemonError::PidFile(format!(
            "refusing to signal unlocked or stale PID file {}",
            path.display()
        )));
    }
    #[cfg(target_os = "linux")]
    return signal_pidfd(&pidfd, pid, signal);
    #[cfg(not(target_os = "linux"))]
    nix::sys::signal::kill(Pid::from_raw(pid), signal)
        .map_err(|error| DaemonError::PidFile(format!("cannot signal process {}: {}", pid, error)))
}

/// Daemon state derived from the PID file.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonStatus {
    /// Daemon is running with the given PID.
    Running(i32),
    /// PID file exists but the named process is not running.
    Stale(i32),
    /// No readable PID file exists.
    NotRunning,
}

/// Checks daemon status read-only, applying the selected policy to both parent lookups.
#[allow(dead_code)]
pub fn check_status<P: AsRef<Path>>(path: P, strict_runtime_paths: bool) -> DaemonStatus {
    let path = normalize_pid_path(path.as_ref());
    match read_pid_file_if_exists(&path, strict_runtime_paths) {
        Ok(Some(pid))
            if daemon_lock_is_held(&path, strict_runtime_paths).unwrap_or(false)
                && is_process_running(pid) =>
        {
            DaemonStatus::Running(pid)
        }
        Ok(Some(pid)) => DaemonStatus::Stale(pid),
        Ok(None) | Err(_) => DaemonStatus::NotRunning,
    }
}

fn daemon_lock_is_held(path: &Path, strict_runtime_paths: bool) -> Result<bool, DaemonError> {
    let lock_path = sibling_lock_path(path);
    let anchor = match AnchoredPath::open_runtime_parent(path, None, strict_runtime_paths) {
        Ok(anchor) => anchor,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(DaemonError::PidFile(format!(
                "cannot open PID parent for {}: {}",
                path.display(),
                error
            )));
        }
    };
    let lock_name = lock_path.file_name().ok_or_else(|| {
        DaemonError::PidFile(format!(
            "lock path {} has no file name",
            lock_path.display()
        ))
    })?;
    let file = match open_file_at(
        &anchor,
        lock_name,
        OFlag::O_RDWR | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW,
        0,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(DaemonError::PidFile(format!(
                "cannot inspect lock {}: {}",
                lock_path.display(),
                error
            )));
        }
    };
    validate_regular_single_link(&file, &lock_path)?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(_available) => Ok(false),
        Err((_file, nix::errno::Errno::EWOULDBLOCK)) => Ok(true),
        Err((_file, error)) => Err(DaemonError::PidFile(format!(
            "cannot inspect lock ownership for {}: {}",
            lock_path.display(),
            error
        ))),
    }
}

#[cfg(target_os = "linux")]
fn open_pidfd(pid: i32) -> Result<OwnedFd, DaemonError> {
    // SAFETY: `pidfd_open` receives a validated positive PID and no pointer arguments.
    let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if descriptor < 0 {
        return Err(DaemonError::PidFile(format!(
            "cannot open stable process handle for {}: {}",
            pid,
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: a successful `pidfd_open` returns one newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(descriptor as i32) })
}

#[cfg(target_os = "linux")]
fn signal_pidfd(
    pidfd: &OwnedFd,
    pid: i32,
    signal: nix::sys::signal::Signal,
) -> Result<(), DaemonError> {
    use std::os::fd::AsRawFd;

    // SAFETY: the pidfd is owned and valid, and both optional pointer arguments are null.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal as libc::c_int,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(DaemonError::PidFile(format!(
            "cannot signal process {} through stable handle: {}",
            pid,
            std::io::Error::last_os_error()
        )))
    }
}

fn is_process_running(pid: i32) -> bool {
    nix::sys::signal::kill(Pid::from_raw(pid), None).is_ok()
}

#[cfg(test)]
mod tests;
