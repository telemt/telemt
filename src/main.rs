//! telemt — Telegram MTProto Proxy

mod api;
mod cli;
mod config;
mod crypto;
mod error;
mod ip_tracker;
#[cfg(test)]
mod ip_tracker_regression_tests;
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

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    maestro::run().await
}
