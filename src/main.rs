//! telemt — Telegram `MTProto` Proxy

#![cfg_attr(
    test,
    allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::expect_used,
        clippy::panic,
        clippy::unwrap_used
    )
)]

mod api;
mod cli;
mod config;
mod crypto;
mod error;
mod ip_tracker;
mod maestro;
mod metrics;
mod network;
mod protocol;
mod proxy;
mod startup;
mod stats;
mod stream;
mod tls_front;
mod transport;
mod util;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(maestro::run())
}
