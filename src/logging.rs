//! Logging configuration for telemt.
//!
//! Supports multiple log destinations:
//! - stderr (default, works with systemd journald)
//! - syslog (Unix only, for traditional init systems)
//! - file (with optional rotation)

#![allow(dead_code)] // Infrastructure module - used via CLI flags

use std::path::Path;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt, reload};

/// Log destination configuration.
#[derive(Debug, Clone, Default)]
pub enum LogDestination {
    /// Log to stderr (default, captured by systemd journald).
    #[default]
    Stderr,
    /// Log to syslog (Unix only).
    #[cfg(unix)]
    Syslog,
    /// Log to a file with optional rotation.
    File {
        path: String,
        /// Rotate daily if true.
        rotate_daily: bool,
    },
}

/// Logging options parsed from CLI/config.
#[derive(Debug, Clone, Default)]
pub struct LoggingOptions {
    /// Where to send logs.
    pub destination: LogDestination,
    /// Disable ANSI colors.
    pub disable_colors: bool,
}

/// Guard that must be held to keep file logging active.
/// When dropped, flushes and closes log files.
pub struct LoggingGuard {
    _guard: Option<tracing_appender::non_blocking::WorkerGuard>,
}

impl LoggingGuard {
    fn new(guard: Option<tracing_appender::non_blocking::WorkerGuard>) -> Self {
        Self { _guard: guard }
    }

    /// Creates a no-op guard for stderr/syslog logging.
    pub fn noop() -> Self {
        Self { _guard: None }
    }
}

/// Initialize the tracing subscriber with the specified options.
///
/// Returns a reload handle for dynamic log level changes and a guard
/// that must be kept alive for file logging.
pub fn init_logging(
    opts: &LoggingOptions,
    initial_filter: &str,
) -> (
    reload::Handle<EnvFilter, impl tracing::Subscriber + Send + Sync>,
    LoggingGuard,
) {
    let (filter_layer, filter_handle) = reload::Layer::new(EnvFilter::new(initial_filter));

    match &opts.destination {
        LogDestination::Stderr => {
            let fmt_layer = fmt::Layer::default()
                .with_ansi(!opts.disable_colors)
                .with_target(true);

            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt_layer)
                .init();

            (filter_handle, LoggingGuard::noop())
        }

        #[cfg(unix)]
        LogDestination::Syslog => {
            // Use a custom fmt layer that writes to syslog
            let fmt_layer = fmt::Layer::default()
                .with_ansi(false)
                .with_target(false)
                .with_level(false)
                .without_time()
                .with_writer(SyslogMakeWriter::new());

            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt_layer)
                .init();

            (filter_handle, LoggingGuard::noop())
        }

        LogDestination::File { path, rotate_daily } => {
            let (non_blocking, guard) = if *rotate_daily {
                // Extract directory and filename prefix
                let path = Path::new(path);
                let dir = path.parent().unwrap_or(Path::new("/var/log"));
                let prefix = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("telemt");

                let file_appender = tracing_appender::rolling::daily(dir, prefix);
                tracing_appender::non_blocking(file_appender)
            } else {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .expect("Failed to open log file");
                tracing_appender::non_blocking(file)
            };

            let fmt_layer = fmt::Layer::default()
                .with_ansi(false)
                .with_target(true)
                .with_writer(non_blocking);

            tracing_subscriber::registry()
                .with(filter_layer)
                .with(fmt_layer)
                .init();

            (filter_handle, LoggingGuard::new(Some(guard)))
        }
    }
}

/// Syslog writer for tracing.
#[cfg(unix)]
#[derive(Clone, Copy)]
struct SyslogMakeWriter;

#[cfg(unix)]
#[derive(Clone, Copy)]
struct SyslogWriter {
    priority: libc::c_int,
}

#[cfg(unix)]
impl SyslogMakeWriter {
    fn new() -> Self {
        // Open syslog connection on first use
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            unsafe {
                // Open syslog with ident "telemt", LOG_PID, LOG_DAEMON facility
                let ident = b"telemt\0".as_ptr() as *const libc::c_char;
                libc::openlog(ident, libc::LOG_PID | libc::LOG_NDELAY, libc::LOG_DAEMON);
            }
        });
        Self
    }
}

#[cfg(unix)]
fn syslog_priority_for_level(level: &tracing::Level) -> libc::c_int {
    match *level {
        tracing::Level::ERROR => libc::LOG_ERR,
        tracing::Level::WARN => libc::LOG_WARNING,
        tracing::Level::INFO => libc::LOG_INFO,
        tracing::Level::DEBUG => libc::LOG_DEBUG,
        tracing::Level::TRACE => libc::LOG_DEBUG,
    }
}

#[cfg(unix)]
impl std::io::Write for SyslogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Convert to C string, stripping newlines
        let msg = String::from_utf8_lossy(buf);
        let msg = msg.trim_end();

        if msg.is_empty() {
            return Ok(buf.len());
        }

        // Write to syslog
        let c_msg = std::ffi::CString::new(msg.as_bytes())
            .unwrap_or_else(|_| std::ffi::CString::new("(invalid utf8)").unwrap());

        unsafe {
            libc::syslog(
                self.priority,
                b"%s\0".as_ptr() as *const libc::c_char,
                c_msg.as_ptr(),
            );
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SyslogMakeWriter {
    type Writer = SyslogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SyslogWriter {
            priority: libc::LOG_INFO,
        }
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        SyslogWriter {
            priority: syslog_priority_for_level(meta.level()),
        }
    }
}

/// Parse log destination from CLI arguments.
pub fn parse_log_destination(args: &[String]) -> LogDestination {
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            #[cfg(unix)]
            "--syslog" => {
                return LogDestination::Syslog;
            }
            "--log-file" => {
                i += 1;
                if i < args.len() {
                    return LogDestination::File {
                        path: args[i].clone(),
                        rotate_daily: false,
                    };
                }
            }
            s if s.starts_with("--log-file=") => {
                return LogDestination::File {
                    path: s.trim_start_matches("--log-file=").to_string(),
                    rotate_daily: false,
                };
            }
            "--log-file-daily" => {
                i += 1;
                if i < args.len() {
                    return LogDestination::File {
                        path: args[i].clone(),
                        rotate_daily: true,
                    };
                }
            }
            s if s.starts_with("--log-file-daily=") => {
                return LogDestination::File {
                    path: s.trim_start_matches("--log-file-daily=").to_string(),
                    rotate_daily: true,
                };
            }
            _ => {}
        }
        i += 1;
    }
    LogDestination::Stderr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_log_destination_default() {
        let args: Vec<String> = vec![];
        assert!(matches!(
            parse_log_destination(&args),
            LogDestination::Stderr
        ));
    }

    #[test]
    fn parse_log_destination_file() {
        let args = vec!["--log-file".to_string(), "/var/log/telemt.log".to_string()];
        match parse_log_destination(&args) {
            LogDestination::File { path, rotate_daily } => {
                assert_eq!(path, "/var/log/telemt.log");
                assert!(!rotate_daily);
            }
            _ => panic!("Expected File destination"),
        }
    }

    #[test]
    fn parse_log_destination_file_daily() {
        let args = vec!["--log-file-daily=/var/log/telemt".to_string()];
        match parse_log_destination(&args) {
            LogDestination::File { path, rotate_daily } => {
                assert_eq!(path, "/var/log/telemt");
                assert!(rotate_daily);
            }
            _ => panic!("Expected File destination"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn parse_log_destination_syslog() {
        let args = vec!["--syslog".to_string()];
        assert!(matches!(
            parse_log_destination(&args),
            LogDestination::Syslog
        ));
    }

    #[test]
    fn parse_log_destination_file_equals_syntax() {
        let args = vec!["--log-file=/tmp/app.log".to_string()];
        match parse_log_destination(&args) {
            LogDestination::File { path, rotate_daily } => {
                assert_eq!(path, "/tmp/app.log");
                assert!(!rotate_daily);
            }
            _ => panic!("Expected File destination"),
        }
    }

    #[test]
    fn parse_log_destination_file_without_value_falls_through() {
        let args = vec!["--log-file".to_string()];
        assert!(matches!(
            parse_log_destination(&args),
            LogDestination::Stderr
        ));
    }

    #[test]
    fn parse_log_destination_daily_separate_arg() {
        let args = vec![
            "--log-file-daily".to_string(),
            "/var/log/daily".to_string(),
        ];
        match parse_log_destination(&args) {
            LogDestination::File { path, rotate_daily } => {
                assert_eq!(path, "/var/log/daily");
                assert!(rotate_daily);
            }
            _ => panic!("Expected File destination"),
        }
    }

    #[test]
    fn parse_log_destination_skips_unrelated_args() {
        let args = vec![
            "--debug".to_string(),
            "--port".to_string(),
            "443".to_string(),
            "--log-file".to_string(),
            "/var/log/proxy.log".to_string(),
            "--other".to_string(),
        ];
        match parse_log_destination(&args) {
            LogDestination::File { path, .. } => assert_eq!(path, "/var/log/proxy.log"),
            _ => panic!("Expected File destination"),
        }
    }

    #[test]
    fn parse_log_destination_first_match_wins() {
        let args = vec![
            "--log-file=/first.log".to_string(),
            "--log-file-daily=/second.log".to_string(),
        ];
        match parse_log_destination(&args) {
            LogDestination::File {
                path, rotate_daily, ..
            } => {
                assert_eq!(path, "/first.log");
                assert!(!rotate_daily);
            }
            _ => panic!("Expected File destination"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn syslog_priority_for_level_mapping() {
        assert_eq!(
            syslog_priority_for_level(&tracing::Level::ERROR),
            libc::LOG_ERR
        );
        assert_eq!(
            syslog_priority_for_level(&tracing::Level::WARN),
            libc::LOG_WARNING
        );
        assert_eq!(
            syslog_priority_for_level(&tracing::Level::INFO),
            libc::LOG_INFO
        );
        assert_eq!(
            syslog_priority_for_level(&tracing::Level::DEBUG),
            libc::LOG_DEBUG
        );
        assert_eq!(
            syslog_priority_for_level(&tracing::Level::TRACE),
            libc::LOG_DEBUG
        );
    }
}
