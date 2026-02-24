//! Stream wrappers for MTProto protocol layers

pub mod state;
pub mod buffer_pool;
pub mod traits;
pub mod crypto_stream;
pub mod tls_stream;
pub mod frame;
pub mod frame_codec;

// Legacy compatibility - will be removed later
pub mod frame_stream;

// Re-export state machine types
#[allow(unused_imports)]
pub use state::{
    StreamState, Transition, PollResult,
    ReadBuffer, WriteBuffer, HeaderBuffer, YieldBuffer,
};

// Re-export buffer pool
#[allow(unused_imports)]
pub use buffer_pool::{BufferPool, PooledBuffer, PoolStats};

// Re-export stream implementations
#[allow(unused_imports)]
pub use crypto_stream::{CryptoReader, CryptoWriter, PassthroughStream};
pub use tls_stream::{FakeTlsReader, FakeTlsWriter};

// Re-export frame types
#[allow(unused_imports)]
pub use frame::{Frame, FrameMeta, FrameCodec as FrameCodecTrait, create_codec};

// Re-export tokio-util compatible codecs
#[allow(unused_imports)]
pub use frame_codec::{
    FrameCodec,
    AbridgedCodec, IntermediateCodec, SecureCodec,
};

// Legacy re-exports for compatibility
#[allow(unused_imports)]
pub use frame_stream::{
    AbridgedFrameReader, AbridgedFrameWriter,
    IntermediateFrameReader, IntermediateFrameWriter,
    SecureIntermediateFrameReader, SecureIntermediateFrameWriter,
    MtprotoFrameReader, MtprotoFrameWriter,
    FrameReaderKind, FrameWriterKind,
};
