//! Stream wrappers for MTProto protocol layers

pub mod buffer_pool;
pub mod crypto_stream;
pub mod frame;
pub mod frame_codec;
pub mod state;
pub mod tls_stream;
pub mod traits;

#[cfg(test)]
mod frame_stream_padding_security_tests;

// Legacy compatibility - will be removed later
pub mod frame_stream;

// Re-export state machine types
#[allow(unused_imports)]
pub use state::{
    HeaderBuffer, PollResult, ReadBuffer, StreamState, Transition, WriteBuffer, YieldBuffer,
};

// Re-export buffer pool
#[allow(unused_imports)]
pub use buffer_pool::{BufferPool, PoolStats, PooledBuffer};

// Re-export stream implementations
#[allow(unused_imports)]
pub use crypto_stream::{CryptoReader, CryptoWriter, PassthroughStream};
pub use tls_stream::{FakeTlsReader, FakeTlsWriter};

// Re-export frame types
#[allow(unused_imports)]
pub use frame::{Frame, FrameCodec as FrameCodecTrait, FrameMeta, create_codec};

// Re-export tokio-util compatible codecs
#[allow(unused_imports)]
pub use frame_codec::{AbridgedCodec, FrameCodec, IntermediateCodec, SecureCodec};

// Legacy re-exports for compatibility
#[allow(unused_imports)]
pub use frame_stream::{
    AbridgedFrameReader, AbridgedFrameWriter, FrameReaderKind, FrameWriterKind,
    IntermediateFrameReader, IntermediateFrameWriter, MtprotoFrameReader, MtprotoFrameWriter,
    SecureIntermediateFrameReader, SecureIntermediateFrameWriter,
};
