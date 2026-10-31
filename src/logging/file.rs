#[cfg(not(unix))]
use std::fs::OpenOptions;
use std::fs::File;
#[cfg(any(test, not(unix)))]
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;

#[cfg(unix)]
use nix::dir::Dir;
#[cfg(unix)]
use nix::fcntl::{OFlag, openat, renameat};
#[cfg(unix)]
use nix::sys::stat::Mode;
#[cfg(unix)]
use nix::unistd::{UnlinkatFlags, dup, unlinkat};

use chrono::{DateTime, Datelike, Duration as ChronoDuration, Utc};

use crate::config::LogRotation;

use super::FileLogOptions;

const CLEANUP_INTERVAL_SECS: i64 = 60;

/// File appender with size rotation and local retention cleanup.
pub(crate) struct BoundedFileAppender {
    options: FileLogOptions,
    dir: PathBuf,
    base_name: String,
    current_path: PathBuf,
    current_size: u64,
    last_cleanup: DateTime<Utc>,
    file: Option<File>,
    #[cfg(unix)]
    dir_fd: OwnedFd,
    now: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

impl BoundedFileAppender {
    /// Opens the appender using the process-level Unix parent-path policy.
    pub(crate) fn new(options: FileLogOptions, strict_runtime_paths: bool) -> io::Result<Self> {
        Self::with_now(options, Box::new(Utc::now), strict_runtime_paths)
    }

    fn with_now(
        options: FileLogOptions,
        now: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
        strict_runtime_paths: bool,
    ) -> io::Result<Self> {
        let path = Path::new(&options.path);
        let dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let base_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("telemt")
            .to_string();

        let start = now();
        let current_path = active_path_for(&dir, &base_name, options.rotation, &start);
        #[cfg(unix)]
        let dir_fd = if strict_runtime_paths {
            crate::util::secure_fs::open_trusted_dir_nofollow_or_create(&dir, 0o750)?
        } else {
            crate::util::secure_fs::open_compatible_dir(&dir, Some(0o750))?
        };
        #[cfg(not(unix))]
        let _ = strict_runtime_paths;
        #[cfg(unix)]
        let (file, current_size) = open_append_file(&dir_fd, &current_path)?;
        #[cfg(not(unix))]
        let (file, current_size) = open_append_file(&current_path)?;
        let mut appender = Self {
            options,
            dir,
            base_name,
            current_path,
            current_size,
            last_cleanup: start,
            file: Some(file),
            #[cfg(unix)]
            dir_fd,
            now,
        };
        appender.cleanup(&start);
        Ok(appender)
    }

    fn now(&self) -> DateTime<Utc> {
        (self.now)()
    }

    fn refresh_active_path(&mut self, now: &DateTime<Utc>) -> io::Result<bool> {
        let next_path = active_path_for(&self.dir, &self.base_name, self.options.rotation, now);
        if next_path == self.current_path {
            return Ok(false);
        }

        self.close_current()?;
        self.current_path = next_path;
        self.open_current()?;
        Ok(true)
    }

    fn rotate_for_size(&mut self, now: &DateTime<Utc>) -> io::Result<()> {
        self.close_current()?;
        let archive_path = self.archive_path(now);
        self.rename_current_if_present(&archive_path)?;
        self.open_current()
    }

    fn archive_path(&self, now: &DateTime<Utc>) -> PathBuf {
        let file_name = self
            .current_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&self.base_name);
        let stamp = now.format("%Y%m%d%H%M%S");
        for seq in 0..1000 {
            let candidate = self.dir.join(format!("{file_name}.{stamp}.{seq}"));
            if !self.path_exists(&candidate) {
                return candidate;
            }
        }
        self.dir.join(format!("{file_name}.{stamp}.overflow"))
    }

    fn open_current(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        let (file, current_size) = open_append_file(&self.dir_fd, &self.current_path)?;
        #[cfg(not(unix))]
        let (file, current_size) = open_append_file(&self.current_path)?;
        self.file = Some(file);
        self.current_size = current_size;
        Ok(())
    }

    fn close_current(&mut self) -> io::Result<()> {
        if let Some(mut file) = self.file.take() {
            file.flush()?;
        }
        Ok(())
    }

    fn should_rotate_for_size(&self, incoming_len: usize) -> bool {
        self.options.max_size_bytes > 0
            && self.current_size > 0
            && self.current_size.saturating_add(incoming_len as u64) > self.options.max_size_bytes
    }

    fn cleanup_due(&self, now: &DateTime<Utc>) -> bool {
        self.options.max_age_secs > 0
            && now.signed_duration_since(self.last_cleanup)
                >= ChronoDuration::seconds(CLEANUP_INTERVAL_SECS)
    }

    fn cleanup(&mut self, now: &DateTime<Utc>) {
        self.last_cleanup = now.clone();
        let Ok(mut candidates) = self.collect_candidates() else {
            return;
        };

        if self.options.max_age_secs > 0 {
            let cutoff = system_time_from_utc(now)
                .checked_sub(Duration::from_secs(self.options.max_age_secs))
                .unwrap_or(UNIX_EPOCH);
            candidates.retain(|candidate| {
                if candidate.is_current || candidate.modified >= cutoff {
                    true
                } else {
                    self.remove_candidate(candidate);
                    false
                }
            });
        }

        if self.options.max_files > 0 && candidates.len() > self.options.max_files {
            let mut archives: Vec<_> = candidates
                .into_iter()
                .filter(|candidate| !candidate.is_current)
                .collect();
            archives.sort_by_key(|candidate| candidate.modified);
            let mut total = archives.len() + 1;
            for candidate in archives {
                if total <= self.options.max_files {
                    break;
                }
                self.remove_candidate(&candidate);
                total -= 1;
            }
        }
    }

    #[cfg(unix)]
    fn path_exists(&self, path: &Path) -> bool {
        let Some(name) = path.file_name() else {
            return true;
        };
        match openat(
            &self.dir_fd,
            name,
            OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        ) {
            Ok(_) => true,
            Err(nix::errno::Errno::ENOENT) => false,
            Err(_) => true,
        }
    }

    #[cfg(not(unix))]
    fn path_exists(&self, path: &Path) -> bool {
        path.exists()
    }

    #[cfg(unix)]
    fn rename_current_if_present(&self, archive_path: &Path) -> io::Result<()> {
        let current_name = self.current_path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "log path has no file name")
        })?;
        let archive_name = archive_path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "archive path has no file name")
        })?;
        match renameat(&self.dir_fd, current_name, &self.dir_fd, archive_name) {
            Ok(()) => Ok(()),
            Err(nix::errno::Errno::ENOENT) => Ok(()),
            Err(error) => Err(io::Error::from_raw_os_error(error as i32)),
        }
    }

    #[cfg(not(unix))]
    fn rename_current_if_present(&self, archive_path: &Path) -> io::Result<()> {
        if self.current_path.exists() {
            fs::rename(&self.current_path, archive_path)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn collect_candidates(&self) -> io::Result<Vec<LogFileCandidate>> {
        use std::os::unix::fs::MetadataExt;

        let descriptor =
            dup(&self.dir_fd).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        let mut directory =
            Dir::from_fd(descriptor).map_err(|error| io::Error::from_raw_os_error(error as i32))?;
        let mut candidates = Vec::new();
        let prefix = format!("{}.", self.base_name);
        for entry in directory.iter().flatten() {
            let bytes = entry.file_name().to_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            let name = OsString::from_vec(bytes.to_vec());
            let path = self.dir.join(&name);
            let is_current = path == self.current_path;
            let Some(name_text) = name.to_str() else {
                continue;
            };
            if !is_current && !name_text.starts_with(&prefix) {
                continue;
            }
            let Ok(descriptor) = openat(
                &self.dir_fd,
                name.as_os_str(),
                OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            ) else {
                continue;
            };
            let file = File::from(descriptor);
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            if !metadata.is_file() || metadata.nlink() != 1 {
                continue;
            }
            candidates.push(LogFileCandidate {
                path,
                modified: metadata.modified().unwrap_or(UNIX_EPOCH),
                is_current,
            });
        }
        Ok(candidates)
    }

    #[cfg(not(unix))]
    fn collect_candidates(&self) -> io::Result<Vec<LogFileCandidate>> {
        let mut candidates = Vec::new();
        let prefix = format!("{}.", self.base_name);
        for entry in fs::read_dir(&self.dir)?.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() {
                continue;
            }
            let is_current = path == self.current_path;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !is_current && !name.starts_with(&prefix) {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            candidates.push(LogFileCandidate {
                path,
                modified: metadata.modified().unwrap_or(UNIX_EPOCH),
                is_current,
            });
        }
        Ok(candidates)
    }

    #[cfg(unix)]
    fn remove_candidate(&self, candidate: &LogFileCandidate) {
        if let Some(name) = candidate.path.file_name() {
            let _ = unlinkat(&self.dir_fd, name, UnlinkatFlags::NoRemoveDir);
        }
    }

    #[cfg(not(unix))]
    fn remove_candidate(&self, candidate: &LogFileCandidate) {
        let _ = fs::remove_file(&candidate.path);
    }
}

impl Write for BoundedFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let now = self.now();
        let rotated_by_time = self.refresh_active_path(&now)?;
        if self.should_rotate_for_size(buf.len()) {
            self.rotate_for_size(&now)?;
            self.cleanup(&now);
        } else if rotated_by_time || self.cleanup_due(&now) {
            self.cleanup(&now);
        }

        let Some(file) = self.file.as_mut() else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "bounded log file is not open",
            ));
        };
        file.write_all(buf)?;
        self.current_size = self.current_size.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = self.file.as_mut() {
            file.flush()
        } else {
            Ok(())
        }
    }
}

struct LogFileCandidate {
    path: PathBuf,
    modified: SystemTime,
    is_current: bool,
}

#[cfg(unix)]
fn open_append_file(dir_fd: &OwnedFd, path: &Path) -> io::Result<(File, u64)> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "log path has no file name"))?;
    let file = crate::util::secure_fs::open_append_regular_at(dir_fd, name, 0o640)?;
    let current_size = file.metadata()?.len();
    Ok((file, current_size))
}

#[cfg(not(unix))]
fn open_append_file(path: &Path) -> io::Result<(File, u64)> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);

    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) => {
            let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            else {
                return Err(error);
            };
            fs::create_dir_all(parent)?;
            options.open(path)?
        }
    };
    let current_size = file.metadata()?.len();
    Ok((file, current_size))
}

fn active_path_for(
    dir: &Path,
    base_name: &str,
    rotation: LogRotation,
    now: &DateTime<Utc>,
) -> PathBuf {
    match rotation {
        LogRotation::Never => dir.join(base_name),
        LogRotation::Minutely | LogRotation::Hourly | LogRotation::Daily | LogRotation::Weekly => {
            dir.join(format!("{base_name}.{}", period_suffix_for(rotation, now)))
        }
    }
}

fn period_suffix_for(rotation: LogRotation, now: &DateTime<Utc>) -> String {
    match rotation {
        LogRotation::Never | LogRotation::Daily => now.format("%Y-%m-%d").to_string(),
        LogRotation::Hourly => now.format("%Y-%m-%d-%H").to_string(),
        LogRotation::Minutely => now.format("%Y-%m-%d-%H-%M").to_string(),
        LogRotation::Weekly => {
            let days_since_sunday = now.weekday().num_days_from_sunday() as i64;
            let week_start = now.date_naive() - ChronoDuration::days(days_since_sunday);
            week_start.format("%Y-%m-%d").to_string()
        }
    }
}

fn system_time_from_utc(now: &DateTime<Utc>) -> SystemTime {
    let duration = Duration::new(now.timestamp().unsigned_abs(), now.timestamp_subsec_nanos());
    if now.timestamp() >= 0 {
        UNIX_EPOCH + duration
    } else {
        UNIX_EPOCH - duration
    }
}

#[cfg(test)]
mod tests;
