//! MiddleProxyStream and HandshakedMiddleConnection
//!
//! ## Types
//!
//! - [`HandshakedMiddleConnection`] — poolable, not yet bound to a client
//! - [`MiddleProxyStream`] — bound to a specific client, split into reader/writer
//! - [`MiddleProxyReader`] — read RPC responses (CBC → frames → RPC parse)
//! - [`MiddleProxyWriter`] — write RPC_PROXY_REQ (RPC build → frames → CBC)

use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tracing::trace;

use crate::crypto::{AesCbcChain, SecureRandom, crc32};
use crate::error::{ProxyError, Result};
use crate::protocol::constants::*;

use super::codec::{
    build_mtproto_frame, build_proxy_req, encode_ip_port_for_rpc, RpcResponse,
};

// ============= HandshakedMiddleConnection =============

/// A fully-handshaked but not-yet-client-bound middle proxy connection.
///
/// Created by [`handshake_middle_proxy`](super::handshake::handshake_middle_proxy).
/// Can be stored in a connection pool and later bound to a specific client
/// via [`into_stream`](Self::into_stream).
pub struct HandshakedMiddleConnection {
    pub(super) stream: TcpStream,
    pub(super) enc_chain: AesCbcChain,
    pub(super) dec_chain: AesCbcChain,
    pub(super) write_seq: i32,
    pub(super) read_seq: i32,
    pub(super) my_ip: IpAddr,
    pub(super) my_port: u16,
    /// Leftover decrypted bytes from CBC alignment during the handshake phase.
    ///
    /// After the nonce + handshake exchange, `read_cbc_exact` may have decrypted
    /// more bytes than were consumed (because CBC operates on 16-byte blocks).
    /// Those residual bytes (typically padding pseudo-frames like `[04,00,00,00]`)
    /// **must** be carried over into the data-relay phase.  If they are dropped,
    /// the CBC chain's internal IV is already past them, yet the MiddleProxyReader
    /// would never see them — causing a silent offset mismatch that corrupts the
    /// very next frame it tries to read.
    ///
    /// In most cases the residual is just padding, but under certain timing
    /// conditions the middle proxy can pipeline data right after the handshake
    /// response inside the same TCP segment, so part of the first real data
    /// frame may already be sitting in this buffer.
    pub(super) dec_buf: Vec<u8>,
}

impl HandshakedMiddleConnection {
    /// Bind this connection to a specific client, producing a [`MiddleProxyStream`].
    ///
    /// Generates a fresh `out_conn_id` and encodes the client and proxy
    /// addresses into the RPC format used for every `RPC_PROXY_REQ`.
    pub fn into_stream(
        self,
        client_addr: SocketAddr,
        proto_tag: ProtoTag,
        ad_tag: [u8; 16],
        rng: &SecureRandom,
    ) -> MiddleProxyStream {
        let out_conn_id: [u8; 8] = rng.bytes(8)
            .try_into()
            .expect("rng always returns exact length");

        let remote_ip_port = encode_ip_port_for_rpc(client_addr);
        let our_ip_port = encode_ip_port_for_rpc(
            SocketAddr::new(self.my_ip, self.my_port),
        );

        let (reader, writer) = self.stream.into_split();

        MiddleProxyStream {
            reader,
            writer,
            enc_chain: self.enc_chain,
            dec_chain: self.dec_chain,
            // CRITICAL: carry over the leftover decrypted bytes from the
            // handshake phase instead of starting with an empty buffer.
            dec_buf: self.dec_buf,
            write_seq: self.write_seq,
            read_seq: self.read_seq,
            out_conn_id,
            remote_ip_port,
            our_ip_port,
            proto_tag,
            ad_tag,
        }
    }
}

// ============= MiddleProxyStream =============

/// A client-bound middle proxy connection ready for RPC_PROXY_REQ I/O.
///
/// Call [`into_split`](Self::into_split) to get independent reader/writer
/// halves for concurrent relay tasks.
pub struct MiddleProxyStream {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    enc_chain: AesCbcChain,
    dec_chain: AesCbcChain,
    dec_buf: Vec<u8>,
    write_seq: i32,
    read_seq: i32,
    out_conn_id: [u8; 8],
    remote_ip_port: [u8; 20],
    our_ip_port: [u8; 20],
    proto_tag: ProtoTag,
    ad_tag: [u8; 16],
}

impl MiddleProxyStream {
    /// Construct from parts (backward compatibility).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        reader: OwnedReadHalf,
        writer: OwnedWriteHalf,
        enc_chain: AesCbcChain,
        dec_chain: AesCbcChain,
        write_seq: i32,
        read_seq: i32,
        out_conn_id: [u8; 8],
        remote_ip_port: [u8; 20],
        our_ip_port: [u8; 20],
        proto_tag: ProtoTag,
        ad_tag: [u8; 16],
    ) -> Self {
        Self {
            reader, writer, enc_chain, dec_chain,
            dec_buf: Vec::with_capacity(256),
            write_seq, read_seq,
            out_conn_id, remote_ip_port, our_ip_port,
            proto_tag, ad_tag,
        }
    }

    /// Split into independent halves for concurrent relay.
    pub fn into_split(self) -> (MiddleProxyReader, MiddleProxyWriter) {
        let reader = MiddleProxyReader {
            reader: self.reader,
            dec_chain: self.dec_chain,
            dec_buf: self.dec_buf,
            read_seq: self.read_seq,
        };
        let writer = MiddleProxyWriter {
            writer: self.writer,
            enc_chain: self.enc_chain,
            write_seq: self.write_seq,
            out_conn_id: self.out_conn_id,
            remote_ip_port: self.remote_ip_port,
            our_ip_port: self.our_ip_port,
            proto_tag: self.proto_tag,
            ad_tag: self.ad_tag,
        };
        (reader, writer)
    }
}

// ============= MiddleProxyReader =============

/// Read half of a middle proxy connection.
///
/// Reads RPC responses through: TCP → AES-CBC decrypt → MTProto frames → RPC parse.
pub struct MiddleProxyReader {
    reader: OwnedReadHalf,
    dec_chain: AesCbcChain,
    dec_buf: Vec<u8>,
    read_seq: i32,
}

impl MiddleProxyReader {
    /// Read the next RPC response from the middle proxy.
    pub async fn read_rpc(&mut self) -> Result<RpcResponse> {
        let frame_data = self.read_encrypted_frame().await?;
        RpcResponse::parse(&frame_data).map_err(ProxyError::Io)
    }

    /// Read one MTProto full frame through CBC decryption.
    ///
    /// Skips padding pseudo-frames (length == 4).
    async fn read_encrypted_frame(&mut self) -> Result<Vec<u8>> {
        loop {
            // Read frame length (4 bytes) through CBC
            let len_bytes = self.read_cbc_exact(4).await?;
            let msg_len = u32::from_le_bytes(
                len_bytes[0..4].try_into().unwrap()
            ) as usize;

            // Skip padding pseudo-frames
            if msg_len == 4 {
                continue;
            }

            // Validate length
            if msg_len < MIN_MSG_LEN || msg_len > MAX_MSG_LEN
                || msg_len % PADDING_FILLER.len() != 0
            {
                return Err(ProxyError::InvalidMessageLength {
                    len: msg_len,
                    min: MIN_MSG_LEN,
                    max: MAX_MSG_LEN,
                });
            }

            // Read remaining: seq(4) + data(msg_len - 12) + crc(4)
            let remaining = msg_len - 4;
            let rest = self.read_cbc_exact(remaining).await?;

            // Verify sequence number
            let msg_seq = i32::from_le_bytes(rest[0..4].try_into().unwrap());
            if msg_seq != self.read_seq {
                return Err(ProxyError::SeqNoMismatch {
                    expected: self.read_seq,
                    got: msg_seq,
                });
            }
            self.read_seq += 1;

            // Extract data
            let data_len = msg_len - 12;
            let data = &rest[4..4 + data_len];

            // Verify CRC32
            let crc_bytes: [u8; 4] = rest[4 + data_len..8 + data_len].try_into().unwrap();
            let expected_crc = u32::from_le_bytes(crc_bytes);

            let mut crc_input = Vec::with_capacity(8 + data_len);
            crc_input.extend_from_slice(&len_bytes);
            crc_input.extend_from_slice(&rest[0..4]); // seq
            crc_input.extend_from_slice(data);
            let computed_crc = crc32(&crc_input);

            if computed_crc != expected_crc {
                return Err(ProxyError::ChecksumMismatch {
                    expected: expected_crc,
                    got: computed_crc,
                });
            }

            trace!(seq = msg_seq, data_len = data_len, "Read encrypted frame");
            return Ok(data.to_vec());
        }
    }

    /// Read exactly `n` bytes through AES-CBC decryption.
    ///
    /// Reads block-aligned (16 bytes) chunks from TCP, decrypts them,
    /// and buffers any excess for subsequent calls.
    async fn read_cbc_exact(&mut self, n: usize) -> Result<Vec<u8>> {
        while self.dec_buf.len() < n {
            let needed = n - self.dec_buf.len();
            let aligned = if needed % 16 == 0 { needed } else { needed + (16 - needed % 16) };

            let mut encrypted = vec![0u8; aligned];
            self.reader.read_exact(&mut encrypted).await.map_err(ProxyError::Io)?;

            let decrypted = self.dec_chain.decrypt(&encrypted)
                .map_err(|e| ProxyError::Crypto(format!("CBC decrypt: {}", e)))?;
            self.dec_buf.extend_from_slice(&decrypted);
        }

        let result = self.dec_buf[..n].to_vec();
        self.dec_buf = self.dec_buf[n..].to_vec();
        Ok(result)
    }
}

// ============= MiddleProxyWriter =============

/// Write half of a middle proxy connection.
///
/// Sends RPC_PROXY_REQ messages through: RPC build → MTProto frame → AES-CBC encrypt → TCP.
pub struct MiddleProxyWriter {
    writer: OwnedWriteHalf,
    enc_chain: AesCbcChain,
    write_seq: i32,
    out_conn_id: [u8; 8],
    remote_ip_port: [u8; 20],
    our_ip_port: [u8; 20],
    proto_tag: ProtoTag,
    ad_tag: [u8; 16],
}

impl MiddleProxyWriter {
    /// Send an RPC_PROXY_REQ wrapping `payload` to the middle proxy.
    ///
    /// `payload` is the raw MTProto data from the client (after frame decoding).
    pub async fn write_proxy_req(&mut self, payload: &[u8], quickack: bool) -> Result<()> {
        let rpc_msg = build_proxy_req(
            &self.out_conn_id,
            &self.remote_ip_port,
            &self.our_ip_port,
            self.proto_tag,
            &self.ad_tag,
            payload,
            quickack,
        );

        // Verify 4-byte alignment (protocol requirement)
        if rpc_msg.len() % 4 != 0 {
            return Err(ProxyError::InvalidHandshake(
                format!("RPC_PROXY_REQ not 4-byte aligned: {}", rpc_msg.len()),
            ));
        }

        // Build MTProto full frame (with CRC32 and padding)
        let frame = build_mtproto_frame(&rpc_msg, self.write_seq);
        self.write_seq += 1;

        // Encrypt with CBC
        let encrypted = self.enc_chain.encrypt(&frame)
            .map_err(|e| ProxyError::Crypto(format!("CBC encrypt frame: {}", e)))?;

        // Send over TCP.
        //
        // No explicit flush() needed: OwnedWriteHalf is an unbuffered TCP
        // stream — write_all pushes bytes directly into the kernel send
        // buffer via the write() syscall.  tokio's TcpStream::poll_flush
        // is a no-op (returns Ready(Ok(()))).
        //
        // Calling flush() after every frame adds no value but costs a
        // traversal through the async write chain on every message.
        self.writer.write_all(&encrypted).await.map_err(ProxyError::Io)?;

        trace!(seq = self.write_seq - 1, frame_len = frame.len(), "Wrote proxy req");
        Ok(())
    }

    /// Shutdown the write half.
    pub async fn shutdown(&mut self) {
        let _ = self.writer.shutdown().await;
    }
}