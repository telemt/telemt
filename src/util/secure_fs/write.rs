use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use nix::fcntl::{OFlag, openat, renameat};
use nix::sys::stat::Mode;
use nix::unistd::{UnlinkatFlags, fsync, unlinkat};

use super::path::{AnchoredPath, errno_to_io};

fn open_regular_at(anchored: &AnchoredPath, flags: OFlag, mode: u32) -> io::Result<std::fs::File> {
    let descriptor = openat(
        anchored.parent(),
        anchored.name(),
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(mode as libc::mode_t),
    )
    .map_err(errno_to_io)?;
    let file = std::fs::File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target must be a regular file",
        ));
    }
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target must have exactly one directory entry",
        ));
    }
    Ok(file)
}

/// Reads a regular file through an anchored parent with an allocation bound.
pub(crate) fn read_regular_limited(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let anchored = AnchoredPath::open(path)?;
    let mut file = open_regular_at(
        &anchored,
        OFlag::O_RDONLY | OFlag::O_NONBLOCK,
        Mode::empty().bits().into(),
    )?;
    let before = file.metadata()?;
    if before.len() > max_bytes as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds configured size limit",
        ));
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::take(&mut file, max_bytes.saturating_add(1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds configured size limit",
        ));
    }
    let after = file.metadata()?;
    if !same_file_version(&before, &after) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file changed while it was read",
        ));
    }
    Ok(bytes)
}

/// Reads a bounded regular file on the blocking pool.
pub(crate) async fn read_regular_limited_async(
    path: std::path::PathBuf,
    max_bytes: usize,
) -> io::Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || read_regular_limited(&path, max_bytes))
        .await
        .map_err(|error| io::Error::other(format!("secure reader task failed: {error}")))?
}

fn same_file_version(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

/// Opens an append-only regular file without following path components or hard links.
pub(crate) fn open_append_regular(path: &Path, mode: u32) -> io::Result<std::fs::File> {
    let anchored = AnchoredPath::open_creating_parents(path, 0o750)?;
    open_regular_at(
        &anchored,
        OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_CREAT,
        mode,
    )
}

/// Opens one append-only file relative to an already anchored directory.
pub(crate) fn open_append_regular_at<Fd: AsFd>(
    parent: Fd,
    name: &OsStr,
    mode: u32,
) -> io::Result<std::fs::File> {
    if Path::new(name).components().count() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "anchored file name must contain one component",
        ));
    }
    let descriptor = openat(
        parent,
        name,
        OFlag::O_WRONLY | OFlag::O_APPEND | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(mode as libc::mode_t),
    )
    .map_err(errno_to_io)?;
    let file = std::fs::File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target must be a regular file",
        ));
    }
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "target must have exactly one directory entry",
        ));
    }
    Ok(file)
}

/// Durably replaces a file through a same-directory descriptor-anchored rename.
pub(crate) fn atomic_replace(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let anchored = AnchoredPath::open_creating_parents(path, 0o750)?;
    atomic_replace_anchored(&anchored, contents, mode)
}

/// Durably replaces a file on the blocking pool.
pub(crate) async fn atomic_replace_async(
    path: std::path::PathBuf,
    contents: Vec<u8>,
    mode: u32,
) -> io::Result<()> {
    tokio::task::spawn_blocking(move || atomic_replace(&path, &contents, mode))
        .await
        .map_err(|error| io::Error::other(format!("secure writer task failed: {error}")))?
}

fn atomic_replace_anchored(anchored: &AnchoredPath, contents: &[u8], mode: u32) -> io::Result<()> {
    let temp_name = format!(".telemt.tmp-{}", rand::random::<u64>());
    let descriptor = openat(
        anchored.parent(),
        temp_name.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(mode as libc::mode_t),
    )
    .map_err(errno_to_io)?;
    let result = write_and_publish(descriptor, anchored, &temp_name, contents);
    if result.is_err() {
        let _ = unlinkat(
            anchored.parent(),
            temp_name.as_str(),
            UnlinkatFlags::NoRemoveDir,
        );
    }
    result
}

fn write_and_publish(
    descriptor: OwnedFd,
    anchored: &AnchoredPath,
    temp_name: &str,
    contents: &[u8],
) -> io::Result<()> {
    let mut file = std::fs::File::from(descriptor);
    file.write_all(contents)?;
    file.sync_all()?;
    renameat(
        anchored.parent(),
        temp_name,
        anchored.parent(),
        anchored.name(),
    )
    .map_err(errno_to_io)?;
    fsync(anchored.parent()).map_err(errno_to_io)
}

/// Exercises publication through a previously anchored parent directory.
#[cfg(test)]
pub(super) fn atomic_replace_after_anchor(
    anchored: &AnchoredPath,
    contents: &[u8],
    mode: u32,
) -> io::Result<()> {
    atomic_replace_anchored(anchored, contents, mode)
}
