//! CLI commands: --init (fire-and-forget setup), daemon options, subcommands
//!
//! Subcommands:
//! - `start [OPTIONS] [config.toml]` - Start the daemon
//! - `stop [--pid-file PATH]` - Stop a running daemon
//! - `reload [--pid-file PATH]` - Reload configuration (SIGHUP)
//! - `status [--pid-file PATH]` - Check daemon status
//! - `run [OPTIONS] [config.toml]` - Run in foreground (default behavior)
//! - `healthcheck [OPTIONS] [config.toml]` - Run control-plane health probe

use rand::RngExt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::healthcheck::{self, HealthcheckMode};

#[cfg(unix)]
use crate::daemon::{self, DEFAULT_PID_FILE, DaemonOptions};

/// CLI subcommand to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subcommand {
    /// Run the proxy (default, or explicit `run` subcommand).
    Run,
    /// Start as daemon (`start` subcommand).
    Start,
    /// Stop a running daemon (`stop` subcommand).
    Stop,
    /// Reload configuration (`reload` subcommand).
    Reload,
    /// Check daemon status (`status` subcommand).
    Status,
    /// Run health probe and exit with status code.
    Healthcheck,
    /// Fire-and-forget setup (`--init`).
    Init,
}

/// Parsed subcommand with its options.
#[derive(Debug)]
pub struct ParsedCommand {
    pub subcommand: Subcommand,
    pub pid_file: PathBuf,
    pub config_path: String,
    pub healthcheck_mode: HealthcheckMode,
    pub healthcheck_mode_invalid: Option<String>,
    #[cfg(unix)]
    pub daemon_opts: DaemonOptions,
    pub init_opts: Option<InitOptions>,
}

impl Default for ParsedCommand {
    fn default() -> Self {
        Self {
            subcommand: Subcommand::Run,
            #[cfg(unix)]
            pid_file: PathBuf::from(DEFAULT_PID_FILE),
            #[cfg(not(unix))]
            pid_file: PathBuf::from("/var/run/telemt.pid"),
            config_path: "config.toml".to_string(),
            healthcheck_mode: HealthcheckMode::Liveness,
            healthcheck_mode_invalid: None,
            #[cfg(unix)]
            daemon_opts: DaemonOptions::default(),
            init_opts: None,
        }
    }
}

/// Parse CLI arguments into a command structure.
pub fn parse_command(args: &[String]) -> ParsedCommand {
    let mut cmd = ParsedCommand::default();

    // Check for --init first (legacy form)
    if args.iter().any(|a| a == "--init") {
        cmd.subcommand = Subcommand::Init;
        cmd.init_opts = parse_init_args(args);
        return cmd;
    }

    // Check for subcommand as first argument
    if let Some(first) = args.first() {
        match first.as_str() {
            "start" => {
                cmd.subcommand = Subcommand::Start;
                #[cfg(unix)]
                {
                    cmd.daemon_opts = parse_daemon_args(args);
                    // Force daemonize for start command
                    cmd.daemon_opts.daemonize = true;
                }
            }
            "stop" => {
                cmd.subcommand = Subcommand::Stop;
            }
            "reload" => {
                cmd.subcommand = Subcommand::Reload;
            }
            "status" => {
                cmd.subcommand = Subcommand::Status;
            }
            "healthcheck" => {
                cmd.subcommand = Subcommand::Healthcheck;
            }
            "run" => {
                cmd.subcommand = Subcommand::Run;
                #[cfg(unix)]
                {
                    cmd.daemon_opts = parse_daemon_args(args);
                }
            }
            _ => {
                // No subcommand, default to Run
                #[cfg(unix)]
                {
                    cmd.daemon_opts = parse_daemon_args(args);
                }
            }
        }
    }

    // Parse remaining options
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            // Skip subcommand names
            "start" | "stop" | "reload" | "status" | "run" | "healthcheck" => {}
            "--mode" => {
                i += 1;
                if i < args.len() {
                    match HealthcheckMode::from_cli_arg(&args[i]) {
                        Some(mode) => {
                            cmd.healthcheck_mode = mode;
                            cmd.healthcheck_mode_invalid = None;
                        }
                        None => {
                            cmd.healthcheck_mode_invalid = Some(args[i].clone());
                        }
                    }
                } else {
                    cmd.healthcheck_mode_invalid = Some(String::new());
                }
            }
            s if s.starts_with("--mode=") => {
                let raw = s.trim_start_matches("--mode=");
                match HealthcheckMode::from_cli_arg(raw) {
                    Some(mode) => {
                        cmd.healthcheck_mode = mode;
                        cmd.healthcheck_mode_invalid = None;
                    }
                    None => {
                        cmd.healthcheck_mode_invalid = Some(raw.to_string());
                    }
                }
            }
            // PID file option (for stop/reload/status)
            "--pid-file" => {
                i += 1;
                if i < args.len() {
                    cmd.pid_file = PathBuf::from(&args[i]);
                    #[cfg(unix)]
                    {
                        cmd.daemon_opts.pid_file = Some(cmd.pid_file.clone());
                    }
                }
            }
            s if s.starts_with("--pid-file=") => {
                cmd.pid_file = PathBuf::from(s.trim_start_matches("--pid-file="));
                #[cfg(unix)]
                {
                    cmd.daemon_opts.pid_file = Some(cmd.pid_file.clone());
                }
            }
            // Config path (positional, non-flag argument)
            s if !s.starts_with('-') => {
                cmd.config_path = s.to_string();
            }
            _ => {}
        }
        i += 1;
    }

    cmd
}

/// Execute a subcommand that doesn't require starting the server.
/// Returns `Some(exit_code)` if the command was handled, `None` if server should start.
#[cfg(unix)]
pub fn execute_subcommand(cmd: &ParsedCommand) -> Option<i32> {
    match cmd.subcommand {
        Subcommand::Stop => Some(cmd_stop(&cmd.pid_file)),
        Subcommand::Reload => Some(cmd_reload(&cmd.pid_file)),
        Subcommand::Status => Some(cmd_status(&cmd.pid_file)),
        Subcommand::Healthcheck => {
            if let Some(invalid_mode) = cmd.healthcheck_mode_invalid.as_ref() {
                if invalid_mode.is_empty() {
                    eprintln!("[telemt] Missing value for --mode (supported: liveness, ready)");
                } else {
                    eprintln!(
                        "[telemt] Invalid --mode value '{invalid_mode}' (supported: liveness, ready)"
                    );
                }
                Some(2)
            } else {
                Some(healthcheck::run(&cmd.config_path, cmd.healthcheck_mode))
            }
        }
        Subcommand::Init => {
            if let Some(opts) = cmd.init_opts.clone() {
                match run_init(opts) {
                    Ok(()) => Some(0),
                    Err(e) => {
                        eprintln!("[telemt] Init failed: {}", e);
                        Some(1)
                    }
                }
            } else {
                Some(1)
            }
        }
        // Run and Start need the server
        Subcommand::Run | Subcommand::Start => None,
    }
}

#[cfg(not(unix))]
pub fn execute_subcommand(cmd: &ParsedCommand) -> Option<i32> {
    match cmd.subcommand {
        Subcommand::Stop | Subcommand::Reload | Subcommand::Status => {
            eprintln!("[telemt] Subcommand not supported on this platform");
            Some(1)
        }
        Subcommand::Healthcheck => {
            if let Some(invalid_mode) = cmd.healthcheck_mode_invalid.as_ref() {
                if invalid_mode.is_empty() {
                    eprintln!("[telemt] Missing value for --mode (supported: liveness, ready)");
                } else {
                    eprintln!(
                        "[telemt] Invalid --mode value '{invalid_mode}' (supported: liveness, ready)"
                    );
                }
                Some(2)
            } else {
                Some(healthcheck::run(&cmd.config_path, cmd.healthcheck_mode))
            }
        }
        Subcommand::Init => {
            if let Some(opts) = cmd.init_opts.clone() {
                match run_init(opts) {
                    Ok(()) => Some(0),
                    Err(e) => {
                        eprintln!("[telemt] Init failed: {}", e);
                        Some(1)
                    }
                }
            } else {
                Some(1)
            }
        }
        Subcommand::Run | Subcommand::Start => None,
    }
}

/// Stop command: send SIGTERM to the running daemon.
#[cfg(unix)]
fn cmd_stop(pid_file: &Path) -> i32 {
    use nix::sys::signal::Signal;

    println!("Stopping telemt daemon...");

    match daemon::signal_pid_file(pid_file, Signal::SIGTERM) {
        Ok(()) => {
            println!("Stop signal sent successfully");

            // Wait for process to exit (up to 10 seconds)
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let daemon::DaemonStatus::NotRunning = daemon::check_status(pid_file) {
                    println!("Daemon stopped");
                    return 0;
                }
            }
            println!("Daemon may still be shutting down");
            0
        }
        Err(e) => {
            eprintln!("Failed to stop daemon: {}", e);
            1
        }
    }
}

/// Reload command: send SIGHUP to trigger config reload.
#[cfg(unix)]
fn cmd_reload(pid_file: &Path) -> i32 {
    use nix::sys::signal::Signal;

    println!("Reloading telemt configuration...");

    match daemon::signal_pid_file(pid_file, Signal::SIGHUP) {
        Ok(()) => {
            println!("Reload signal sent successfully");
            0
        }
        Err(e) => {
            eprintln!("Failed to reload daemon: {}", e);
            1
        }
    }
}

/// Status command: check if daemon is running.
#[cfg(unix)]
fn cmd_status(pid_file: &Path) -> i32 {
    match daemon::check_status(pid_file) {
        daemon::DaemonStatus::Running(pid) => {
            println!("telemt is running (pid {})", pid);
            0
        }
        daemon::DaemonStatus::Stale(pid) => {
            println!("telemt is not running (stale pid file, was pid {})", pid);
            // Clean up stale PID file
            let _ = std::fs::remove_file(pid_file);
            1
        }
        daemon::DaemonStatus::NotRunning => {
            println!("telemt is not running");
            1
        }
    }
}

/// Options for the init command
#[derive(Debug, Clone)]
pub struct InitOptions {
    pub port: u16,
    pub domain: String,
    pub secret: Option<String>,
    pub username: String,
    pub config_dir: PathBuf,
    pub no_start: bool,
}

/// Parse daemon-related options from CLI args.
#[cfg(unix)]
pub fn parse_daemon_args(args: &[String]) -> DaemonOptions {
    let mut opts = DaemonOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--daemon" | "-d" => {
                opts.daemonize = true;
            }
            "--foreground" | "-f" => {
                opts.foreground = true;
            }
            "--pid-file" => {
                i += 1;
                if i < args.len() {
                    opts.pid_file = Some(PathBuf::from(&args[i]));
                }
            }
            s if s.starts_with("--pid-file=") => {
                opts.pid_file = Some(PathBuf::from(s.trim_start_matches("--pid-file=")));
            }
            "--run-as-user" => {
                i += 1;
                if i < args.len() {
                    opts.user = Some(args[i].clone());
                }
            }
            s if s.starts_with("--run-as-user=") => {
                opts.user = Some(s.trim_start_matches("--run-as-user=").to_string());
            }
            "--run-as-group" => {
                i += 1;
                if i < args.len() {
                    opts.group = Some(args[i].clone());
                }
            }
            s if s.starts_with("--run-as-group=") => {
                opts.group = Some(s.trim_start_matches("--run-as-group=").to_string());
            }
            "--working-dir" => {
                i += 1;
                if i < args.len() {
                    opts.working_dir = Some(PathBuf::from(&args[i]));
                }
            }
            s if s.starts_with("--working-dir=") => {
                opts.working_dir = Some(PathBuf::from(s.trim_start_matches("--working-dir=")));
            }
            _ => {}
        }
        i += 1;
    }

    opts
}

impl Default for InitOptions {
    fn default() -> Self {
        Self {
            port: 443,
            domain: "www.google.com".to_string(),
            secret: None,
            username: "user".to_string(),
            config_dir: PathBuf::from("/etc/telemt"),
            no_start: false,
        }
    }
}

/// Parse --init subcommand options from CLI args.
///
/// Returns `Some(InitOptions)` if `--init` was found, `None` otherwise.
pub fn parse_init_args(args: &[String]) -> Option<InitOptions> {
    if !args.iter().any(|a| a == "--init") {
        return None;
    }

    let mut opts = InitOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                i += 1;
                if i < args.len() {
                    opts.port = args[i].parse().unwrap_or(443);
                }
            }
            "--domain" => {
                i += 1;
                if i < args.len() {
                    opts.domain = args[i].clone();
                }
            }
            "--secret" => {
                i += 1;
                if i < args.len() {
                    opts.secret = Some(args[i].clone());
                }
            }
            "--user" => {
                i += 1;
                if i < args.len() {
                    opts.username = args[i].clone();
                }
            }
            "--config-dir" => {
                i += 1;
                if i < args.len() {
                    opts.config_dir = PathBuf::from(&args[i]);
                }
            }
            "--no-start" => {
                opts.no_start = true;
            }
            _ => {}
        }
        i += 1;
    }

    Some(opts)
}

/// Run the fire-and-forget setup.
pub fn run_init(opts: InitOptions) -> Result<(), Box<dyn std::error::Error>> {
    use crate::service::{self, InitSystem, ServiceOptions};

    eprintln!("[telemt] Fire-and-forget setup");
    eprintln!();

    // 1. Detect init system
    let init_system = service::detect_init_system();
    eprintln!("[+] Detected init system: {}", init_system);

    // 2. Generate or validate secret
    let secret = match opts.secret {
        Some(s) => {
            if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                eprintln!("[error] Secret must be exactly 32 hex characters");
                std::process::exit(1);
            }
            s
        }
        None => generate_secret(),
    };

    eprintln!("[+] Secret: {}", secret);
    eprintln!("[+] User:   {}", opts.username);
    eprintln!("[+] Port:   {}", opts.port);
    eprintln!("[+] Domain: {}", opts.domain);

    // 3. Create config directory
    fs::create_dir_all(&opts.config_dir)?;
    let config_path = opts.config_dir.join("config.toml");

    // 4. Write config
    let config_content = generate_config(&opts.username, &secret, opts.port, &opts.domain);
    fs::write(&config_path, &config_content)?;
    eprintln!("[+] Config written to {}", config_path.display());

    // 5. Generate and write service file
    let exe_path =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/telemt"));

    let service_opts = ServiceOptions {
        exe_path: &exe_path,
        config_path: &config_path,
        user: None, // Let systemd/init handle user
        group: None,
        pid_file: "/var/run/telemt.pid",
        working_dir: Some("/var/lib/telemt"),
        description: "Telemt MTProxy - Telegram MTProto Proxy",
    };

    let service_path = service::service_file_path(init_system);
    let service_content = service::generate_service_file(init_system, &service_opts);

    // Ensure parent directory exists
    if let Some(parent) = Path::new(service_path).parent() {
        let _ = fs::create_dir_all(parent);
    }

    match fs::write(service_path, &service_content) {
        Ok(()) => {
            eprintln!("[+] Service file written to {}", service_path);

            // Make script executable for OpenRC/FreeBSD
            #[cfg(unix)]
            if init_system == InitSystem::OpenRC || init_system == InitSystem::FreeBSDRc {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(service_path)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(service_path, perms)?;
            }
        }
        Err(e) => {
            eprintln!("[!] Cannot write service file (run as root?): {}", e);
            eprintln!("[!] Manual service file content:");
            eprintln!("{}", service_content);

            // Still print links and installation instructions
            eprintln!();
            eprintln!("{}", service::installation_instructions(init_system));
            print_links(&opts.username, &secret, opts.port, &opts.domain);
            return Ok(());
        }
    }

    // 6. Install and enable service based on init system
    match init_system {
        InitSystem::Systemd => {
            run_cmd("systemctl", &["daemon-reload"]);
            run_cmd("systemctl", &["enable", "telemt.service"]);
            eprintln!("[+] Service enabled");

            if !opts.no_start {
                run_cmd("systemctl", &["start", "telemt.service"]);
                eprintln!("[+] Service started");

                std::thread::sleep(std::time::Duration::from_secs(1));
                let status = Command::new("systemctl")
                    .args(["is-active", "telemt.service"])
                    .output();

                match status {
                    Ok(out) if out.status.success() => {
                        eprintln!("[+] Service is running");
                    }
                    _ => {
                        eprintln!("[!] Service may not have started correctly");
                        eprintln!("[!] Check: journalctl -u telemt.service -n 20");
                    }
                }
            } else {
                eprintln!("[+] Service not started (--no-start)");
                eprintln!("[+] Start manually: systemctl start telemt.service");
            }
        }
        InitSystem::OpenRC => {
            run_cmd("rc-update", &["add", "telemt", "default"]);
            eprintln!("[+] Service enabled");

            if !opts.no_start {
                run_cmd("rc-service", &["telemt", "start"]);
                eprintln!("[+] Service started");
            } else {
                eprintln!("[+] Service not started (--no-start)");
                eprintln!("[+] Start manually: rc-service telemt start");
            }
        }
        InitSystem::FreeBSDRc => {
            run_cmd("sysrc", &["telemt_enable=YES"]);
            eprintln!("[+] Service enabled");

            if !opts.no_start {
                run_cmd("service", &["telemt", "start"]);
                eprintln!("[+] Service started");
            } else {
                eprintln!("[+] Service not started (--no-start)");
                eprintln!("[+] Start manually: service telemt start");
            }
        }
        InitSystem::Unknown => {
            eprintln!("[!] Unknown init system - service file written but not installed");
            eprintln!("[!] You may need to install it manually");
        }
    }

    eprintln!();

    // 7. Print links
    print_links(&opts.username, &secret, opts.port, &opts.domain);

    Ok(())
}

fn generate_secret() -> String {
    let mut rng = rand::rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.random::<u8>()).collect();
    hex::encode(bytes)
}

fn generate_config(username: &str, secret: &str, port: u16, domain: &str) -> String {
    format!(
        r#"# Telemt MTProxy — auto-generated config
# Re-run `telemt --init` to regenerate

show_link = ["{username}"]

[general]
# prefer_ipv6 is deprecated; use [network].prefer
prefer_ipv6 = false
fast_mode = true
use_middle_proxy = false
log_level = "normal"
desync_all_full = false
update_every = 43200
hardswap = false
me_pool_drain_ttl_secs = 90
me_instadrain = false
me_pool_drain_threshold = 32
me_pool_drain_soft_evict_grace_secs = 10
me_pool_drain_soft_evict_per_writer = 2
me_pool_drain_soft_evict_budget_per_core = 16
me_pool_drain_soft_evict_cooldown_ms = 1000
me_bind_stale_mode = "never"
me_pool_min_fresh_ratio = 0.8
me_reinit_drain_timeout_secs = 90
tg_connect = 10

[network]
ipv4 = true
ipv6 = true
prefer = 4
multipath = false

[general.modes]
classic = false
secure = false
tls = true

[server]
listen_addr_ipv4 = "0.0.0.0"
listen_addr_ipv6 = "::"

[[server.listeners]]
ip = "0.0.0.0"
port = {port}
# reuse_allow = false # Set true only when intentionally running multiple telemt instances on same port

[[server.listeners]]
ip = "::"
port = {port}

[timeouts]
client_first_byte_idle_secs = 300
client_handshake = 60
client_keepalive = 60
client_ack = 300

[censorship]
tls_domain = "{domain}"
mask = true
mask_port = 443
fake_cert_len = 2048
serverhello_compact = false
tls_full_cert_ttl_secs = 90

[access]
user_max_tcp_conns_global_each = 0
replay_check_len = 65536
replay_window_secs = 120
ignore_time_skew = false

[access.users]
{username} = "{secret}"

[[upstreams]]
type = "direct"
enabled = true
weight = 10
"#,
        username = username,
        secret = secret,
        port = port,
        domain = domain,
    )
}

fn run_cmd(cmd: &str, args: &[&str]) {
    match Command::new(cmd).args(args).output() {
        Ok(output) => {
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("[!] {} {} failed: {}", cmd, args.join(" "), stderr.trim());
            }
        }
        Err(e) => {
            eprintln!("[!] Failed to run {} {}: {}", cmd, args.join(" "), e);
        }
    }
}

fn print_links(username: &str, secret: &str, port: u16, domain: &str) {
    let domain_hex = hex::encode(domain);

    println!("=== Proxy Links ===");
    println!("[{}]", username);
    println!(
        "  EE-TLS:  tg://proxy?server=YOUR_SERVER_IP&port={}&secret=ee{}{}",
        port, secret, domain_hex
    );
    println!();
    println!("Replace YOUR_SERVER_IP with your server's public IP.");
    println!("The proxy will auto-detect and display the correct link on startup.");
    println!("Check: journalctl -u telemt.service | head -30");
    println!("===================");
}
