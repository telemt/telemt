//! Descriptor-anchored filesystem operations for privileged runtime paths.
//!
//! Submodules:
//! - `path`: strict or compatible directory traversal and anchored path ownership
//! - `write`: regular-file opening and durable atomic replacement

mod path;
mod write;

pub(crate) use path::{
    AnchoredPath, chdir_nofollow_or_create, open_compatible_dir, open_dir_nofollow,
    open_trusted_dir_nofollow_or_create,
};
#[cfg(test)]
pub(crate) use write::open_append_regular;
pub(crate) use write::{
    atomic_replace, atomic_replace_async, open_append_regular_at, read_regular_limited,
    read_regular_limited_async,
};

#[cfg(test)]
mod tests;
