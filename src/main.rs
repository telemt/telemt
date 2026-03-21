//! telemt — Telegram MTProto Proxy

mod api;
mod cli;
mod config;
mod crypto;
mod error;
mod ip_tracker;
#[cfg(test)]
#[path = "tests/ip_tracker_regression_tests.rs"]
mod ip_tracker_regression_tests;
#[cfg(test)]
#[path = "tests/ip_tracker_hotpath_adversarial_tests.rs"]
mod ip_tracker_hotpath_adversarial_tests;
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
