use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path};

use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::{Mode, mkdirat};

const DIRECTORY_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// An immutable parent-directory descriptor paired with one final path component.
pub(crate) struct AnchoredPath {
    parent: OwnedFd,
    name: OsString,
}

impl AnchoredPath {
    /// Opens every parent component without following symbolic links.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        Self::open_with_parent_creation(path, None)
    }

    /// Creates missing parent directories while traversing without symbolic links.
    pub(crate) fn open_creating_parents(path: &Path, mode: u32) -> io::Result<Self> {
        Self::open_with_parent_creation(path, Some(mode))
    }

    /// Opens a parent chain that cannot be renamed by group or world users.
    pub(crate) fn open_trusted_parent(path: &Path) -> io::Result<Self> {
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
            .to_os_string();
        let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
        let parent = open_trusted_dir_nofollow(parent_path)?;
        Ok(Self { parent, name })
    }

    /// Creates missing parents and opens a chain protected from untrusted renames.
    pub(crate) fn open_trusted_parent_or_create(path: &Path, mode: u32) -> io::Result<Self> {
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
            .to_os_string();
        let parent_path = path.parent().unwrap_or_else(|| Path::new("."));
        let parent = open_trusted_dir_nofollow_or_create(parent_path, mode)?;
        Ok(Self { parent, name })
    }

    /// Anchors a runtime parent, applying trusted traversal only when explicitly requested.
    pub(crate) fn open_runtime_parent(
        path: &Path,
        create_mode: Option<u32>,
        strict_runtime_paths: bool,
    ) -> io::Result<Self> {
        if strict_runtime_paths {
            return match create_mode {
                Some(mode) => Self::open_trusted_parent_or_create(path, mode),
                None => Self::open_trusted_parent(path),
            };
        }
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
            .to_os_string();
        let parent =
            open_compatible_dir(path.parent().unwrap_or_else(|| Path::new(".")), create_mode)?;
        Ok(Self { parent, name })
    }

    fn open_with_parent_creation(path: &Path, create_mode: Option<u32>) -> io::Result<Self> {
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?
            .to_os_string();
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let parent = match create_mode {
            Some(mode) => open_or_create_dir_nofollow(parent, mode)?,
            None => open_dir_nofollow(parent)?,
        };
        Ok(Self { parent, name })
    }

    /// Returns the anchored parent descriptor.
    pub(crate) fn parent(&self) -> &OwnedFd {
        &self.parent
    }

    /// Returns the single final component resolved relative to the parent descriptor.
    pub(crate) fn name(&self) -> &OsStr {
        &self.name
    }
}

/// Opens a directory by walking every component with `O_NOFOLLOW`.
pub(crate) fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    open_dir_components(path, None, false)
}

fn open_or_create_dir_nofollow(path: &Path, mode: u32) -> io::Result<OwnedFd> {
    open_dir_components(path, Some(mode), false)
}

/// Opens a directory after securely creating any missing components.
pub(crate) fn open_dir_nofollow_or_create(path: &Path, mode: u32) -> io::Result<OwnedFd> {
    open_or_create_dir_nofollow(path, mode)
}

/// Opens or creates a directory chain protected from untrusted entry replacement.
pub(crate) fn open_trusted_dir_nofollow_or_create(path: &Path, mode: u32) -> io::Result<OwnedFd> {
    open_dir_components(path, Some(mode), true)
}

/// Follows parent-directory symlinks without imposing ownership or permission policy.
pub(crate) fn open_compatible_dir(path: &Path, create_mode: Option<u32>) -> io::Result<OwnedFd> {
    let path = if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    };
    if let Some(mode) = create_mode {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(mode)
            .create(path)?;
    }
    // Retain the resolved directory inode so subsequent file operations do not rewalk the path.
    open(path, DIRECTORY_FLAGS & !OFlag::O_NOFOLLOW, Mode::empty()).map_err(errno_to_io)
}

/// Opens a directory only when its entire path is owned by root or the effective user.
fn open_trusted_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    open_dir_components(path, None, true)
}

fn open_dir_components(
    path: &Path,
    create_mode: Option<u32>,
    require_trusted: bool,
) -> io::Result<OwnedFd> {
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::ParentDir => names.push(OsString::from("..")),
            Component::Prefix(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported path prefix",
                ));
            }
        }
    }
    let start = if path.is_absolute() {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut current = open(start, DIRECTORY_FLAGS, Mode::empty()).map_err(errno_to_io)?;
    if require_trusted {
        validate_trusted_directory(&current, !names.is_empty())?;
    }
    let component_count = names.len();
    for (index, name) in names.into_iter().enumerate() {
        let next = match openat(&current, name.as_os_str(), DIRECTORY_FLAGS, Mode::empty()) {
            Ok(descriptor) => descriptor,
            Err(nix::errno::Errno::ENOENT) if create_mode.is_some() => {
                let mode = Mode::from_bits_truncate(create_mode.unwrap_or(0o750) as libc::mode_t);
                match mkdirat(&current, name.as_os_str(), mode) {
                    Ok(()) | Err(nix::errno::Errno::EEXIST) => {}
                    Err(error) => return Err(errno_to_io(error)),
                }
                openat(&current, name.as_os_str(), DIRECTORY_FLAGS, Mode::empty())
                    .map_err(errno_to_io)?
            }
            Err(error) => return Err(errno_to_io(error)),
        };
        if require_trusted {
            validate_trusted_directory(&next, index + 1 < component_count)?;
        }
        current = next;
    }
    Ok(current)
}

fn validate_trusted_directory(descriptor: &OwnedFd, allow_sticky_parent: bool) -> io::Result<()> {
    let file = std::fs::File::from(descriptor.try_clone()?);
    let metadata = file.metadata()?;
    let effective_uid = nix::unistd::Uid::effective().as_raw();
    let mode = metadata.permissions().mode();
    let writable_by_others = mode & 0o022 != 0;
    let protected_sticky_parent = allow_sticky_parent && mode & 0o1000 != 0;
    if !metadata.is_dir()
        || (metadata.uid() != 0 && metadata.uid() != effective_uid)
        || (writable_by_others && !protected_sticky_parent)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "directory path is not owned and protected from group/world writes",
        ));
    }
    Ok(())
}

/// Creates missing components and changes cwd to the exact opened directory inode.
pub(crate) fn chdir_nofollow_or_create(path: &Path, mode: u32) -> io::Result<()> {
    let descriptor = open_dir_nofollow_or_create(path, mode)?;
    nix::unistd::fchdir(&descriptor).map_err(errno_to_io)
}

/// Converts one `nix` errno without discarding its platform error code.
pub(super) fn errno_to_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}
