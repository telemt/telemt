# Code Mode Rules for Telemt

## Error Handling
- Always use [`ProxyError`](src/error.rs:168) from [`src/error.rs`](src/error.rs) for proxy operations
- [`HandshakeResult<T,R,W>`](src/error.rs:292) returns streams on bad client - these MUST be returned for masking, never dropped
- Use [`Recoverable`](src/error.rs:110) trait to check if errors are retryable

## Configuration Changes
- [`ProxyConfig::load()`](src/config/mod.rs:641) auto-mutates config - new fields should have defaults
- DC203 override is auto-injected if missing - do not remove this behavior
- When adding config fields, add migration logic in [`ProxyConfig::load()`](src/config/mod.rs:641)

## Crypto Code
- [`SecureRandom`](src/crypto/random.rs) from [`src/crypto/random.rs`](src/crypto/random.rs) must be used for all crypto operations
- Never use `rand::thread_rng()` directly - use the shared `Arc<SecureRandom>`

## Stream Handling
- Buffer pool [`BufferPool`](src/stream/buffer_pool.rs) is shared via Arc - always use it instead of allocating
- Frame codecs in [`src/stream/frame_codec.rs`](src/stream/frame_codec.rs) implement tokio-util's Encoder/Decoder traits

## Testing
- Tests are inline in modules using `#[cfg(test)]`
- Use `cargo test --lib <module_name>` to run tests for specific modules
