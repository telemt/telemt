use std::io::{Error, ErrorKind, Result};
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::config::ClientMssPrefix;
use crate::protocol::constants::TLS_RECORD_HANDSHAKE;

/// Size of the TCP timestamps option with padding. When timestamps are
/// negotiated, a segment at MSS `m` carries `m - 12` payload bytes.
const TCP_TIMESTAMPS_OVERHEAD: usize = 12;

/// `TCPI_OPT_TIMESTAMPS` from `linux/tcp.h`.
const TCPI_OPT_TIMESTAMPS: u8 = 1;

/// TLS record header length.
const TLS_RECORD_HEADER_LEN: usize = 5;

/// Ceiling of the [`ClientMssPrefix::ServerHello`] prefix. It covers a
/// ServerHello with an X25519MLKEM768 key share (about 1.2 KiB) and bounds the
/// chunked region if the first record is unexpectedly large.
pub(crate) const SERVER_HELLO_PREFIX_MAX: usize = 2048;

/// Returns how many leading bytes of `data` are written in small chunks.
///
/// [`ClientMssPrefix::ServerHello`] ends at the first TLS record when `data`
/// starts with a complete handshake record. Otherwise the whole response is
/// chunked, which keeps the conservative behavior for unexpected input.
pub(crate) fn chunked_prefix_len(data: &[u8], prefix: ClientMssPrefix) -> usize {
    match prefix {
        ClientMssPrefix::Full => data.len(),
        ClientMssPrefix::Bytes(bytes) => usize::from(bytes).min(data.len()),
        ClientMssPrefix::ServerHello => {
            if data.len() < TLS_RECORD_HEADER_LEN || data[0] != TLS_RECORD_HANDSHAKE {
                return data.len();
            }
            let record_end =
                TLS_RECORD_HEADER_LEN + usize::from(u16::from_be_bytes([data[3], data[4]]));
            if record_end > data.len() {
                return data.len();
            }
            record_end.min(SERVER_HELLO_PREFIX_MAX)
        }
    }
}

/// Returns the payload of one chunk for handshake MSS `fragment_size`.
///
/// The value matches what the kernel would put in one segment at that MSS:
/// the timestamps option is subtracted when negotiated, and the result never
/// exceeds the current send MSS of the connection.
pub(crate) fn chunk_payload_len(fragment_size: usize, tcpi_options: u8, snd_mss: u32) -> usize {
    let mut payload = fragment_size;
    if tcpi_options & TCPI_OPT_TIMESTAMPS != 0 {
        payload = payload.saturating_sub(TCP_TIMESTAMPS_OVERHEAD);
    }
    if snd_mss > 0 {
        payload = payload.min(usize::try_from(snd_mss).unwrap_or(usize::MAX));
    }
    payload.max(1)
}

fn tcp_info(fd: RawFd) -> Result<libc::tcp_info> {
    // SAFETY: tcp_info is a plain C struct; all-zero is a valid value.
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_INFO,
            &mut info as *mut libc::tcp_info as *mut libc::c_void,
            &mut length,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(info)
}

fn set_tcp_nodelay(fd: RawFd) -> Result<()> {
    let enabled: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &enabled as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

/// Writes `data` to `async_fd`, waiting for writability when the send buffer
/// is full. A partial send leaves the rest of `data` for the next call, so
/// with `MSG_EOR` the kernel still closes the skb only at the end of `data`.
async fn send_all(async_fd: &AsyncFd<std::os::fd::OwnedFd>, data: &[u8], flags: i32) -> Result<()> {
    let mut offset = 0;
    while offset < data.len() {
        let mut writable = async_fd.writable().await?;
        let sent = match writable.try_io(|inner| {
            let remaining = &data[offset..];
            let sent = unsafe {
                libc::send(
                    inner.get_ref().as_raw_fd(),
                    remaining.as_ptr().cast::<libc::c_void>(),
                    remaining.len(),
                    libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL | flags,
                )
            };
            if sent < 0 {
                Err(Error::last_os_error())
            } else if sent == 0 {
                Err(Error::new(
                    ErrorKind::WriteZero,
                    "fragmented TCP send returned zero",
                ))
            } else {
                Ok(sent as usize)
            }
        }) {
            Ok(Ok(sent)) => sent,
            Ok(Err(error)) if error.kind() == ErrorKind::Interrupted => continue,
            Ok(Err(error)) => return Err(error),
            Err(_) => continue,
        };
        offset += sent;
    }
    Ok(())
}

/// Sends an initial TCP response using best-effort userspace write chunking.
///
/// `fd` must refer to a connected, nonblocking TCP socket and remain valid for
/// the duration of this call. The caller retains ownership of the original fd.
///
/// The leading part selected by `prefix` is written in chunks that each fit
/// one segment at MSS `fragment_size`, every chunk with `MSG_EOR` so the
/// kernel neither appends to it nor collapses it on retransmission. The rest
/// is written in one call and leaves at the connection MSS; the `MSG_EOR` on
/// the last chunk keeps it from joining the small tail. The socket MSS itself
/// is not changed: `TCP_MAXSEG` on an established Linux socket does not affect
/// outgoing segments. TCP offloads may still coalesce capture boundaries.
pub(crate) async fn send_tcp_fragmented_fd(
    fd: RawFd,
    data: &[u8],
    fragment_size: usize,
    prefix: ClientMssPrefix,
) -> Result<()> {
    if fragment_size == 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "TCP fragment size must be greater than zero",
        ));
    }
    if data.is_empty() {
        return Ok(());
    }
    if fd < 0 {
        return Err(Error::from_raw_os_error(libc::EBADF));
    }

    // SAFETY: the caller guarantees that fd remains open for this call.
    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
    let duplicated_fd = borrowed_fd.try_clone_to_owned()?;
    let async_fd = AsyncFd::with_interest(duplicated_fd, Interest::WRITABLE)?;
    let raw_fd = async_fd.get_ref().as_raw_fd();

    // Every chunk must leave immediately, without Nagle.
    set_tcp_nodelay(raw_fd)?;
    let chunk = match tcp_info(raw_fd) {
        Ok(info) => chunk_payload_len(fragment_size, info.tcpi_options, info.tcpi_snd_mss),
        Err(_) => fragment_size,
    };

    let (head, tail) = data.split_at(chunked_prefix_len(data, prefix));
    for fragment in head.chunks(chunk) {
        send_all(&async_fd, fragment, libc::MSG_EOR).await?;
    }
    send_all(&async_fd, tail, 0).await
}

#[cfg(test)]
#[path = "fragmented_send_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "fragmented_send_wire_tests.rs"]
mod wire_tests;
