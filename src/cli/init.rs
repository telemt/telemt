use std::path::{Path, PathBuf};

use rand::RngExt;

#[cfg(unix)]
use crate::util::trusted_command::trusted_helper_command;

/// Options for the fire-and-forget init command.
#[derive(Debug, Clone)]
pub struct InitOptions {
    /// Public listener port.
    pub port: u16,
    /// TLS camouflage domain.
    pub domain: String,
    /// Optional pre-generated proxy secret.
    pub secret: Option<String>,
    /// Initial access username.
    pub username: String,
    /// Destination directory for generated configuration.
    pub config_dir: PathBuf,
    /// Generate service files without starting the service.
    pub no_start: bool,
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

    let init_system = service::detect_init_system();
    eprintln!("[+] Detected init system: {}", init_system);

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

    let config_path = opts.config_dir.join("config.toml");
    let config_content = generate_config(&opts.username, &secret, opts.port, &opts.domain);
    write_init_file(&config_path, &config_content, 0o600)?;
    eprintln!("[+] Config written to {}", config_path.display());

    let exe_path =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("/usr/local/bin/telemt"));
    let service_opts = ServiceOptions {
        exe_path: &exe_path,
        config_path: &config_path,
        // Let the selected init system manage process identity.
        user: None,
        group: None,
        pid_file: "/var/run/telemt.pid",
        working_dir: Some("/var/lib/telemt"),
        description: "Telemt MTProxy - Telegram MTProto Proxy",
    };

    let service_path = service::service_file_path(init_system);
    let service_content = service::generate_service_file(init_system, &service_opts);
    let service_mode = if init_system == InitSystem::OpenRC || init_system == InitSystem::FreeBSDRc
    {
        0o755
    } else {
        0o644
    };
    match write_init_file(Path::new(service_path), &service_content, service_mode) {
        Ok(()) => {
            eprintln!("[+] Service file written to {}", service_path);
        }
        Err(e) => {
            eprintln!("[!] Cannot write service file (run as root?): {}", e);
            eprintln!("[!] Manual service file content:");
            eprintln!("{}", service_content);
            eprintln!();
            eprintln!("{}", service::installation_instructions(init_system));
            print_links(&opts.username, &secret, opts.port, &opts.domain);
            return Ok(());
        }
    }

    match init_system {
        InitSystem::Systemd => {
            run_cmd("systemctl", &["daemon-reload"]);
            run_cmd("systemctl", &["enable", "telemt.service"]);
            eprintln!("[+] Service enabled");

            if !opts.no_start {
                run_cmd("systemctl", &["start", "telemt.service"]);
                eprintln!("[+] Service started");

                std::thread::sleep(std::time::Duration::from_secs(1));
                #[cfg(unix)]
                let status = trusted_helper_command("systemctl").and_then(|mut command| {
                    command.args(["is-active", "telemt.service"]).output().ok()
                });
                #[cfg(not(unix))]
                let status: Option<std::process::Output> = None;
                match status {
                    Some(out) if out.status.success() => {
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
    print_links(&opts.username, &secret, opts.port, &opts.domain);
    Ok(())
}

fn write_init_file(path: &Path, contents: &str, mode: u32) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        crate::util::secure_fs::atomic_replace(path, contents.as_bytes(), mode)
    }
    #[cfg(not(unix))]
    {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let _ = mode;
        std::fs::write(path, contents)
    }
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
# Optional per-upstream DC family policy:
# ipv6 = true
# prefer = 6
"#,
        username = username,
        secret = secret,
        port = port,
        domain = domain,
    )
}

fn run_cmd(cmd: &str, args: &[&str]) {
    #[cfg(not(unix))]
    {
        let _ = args;
        eprintln!("[!] Refusing unavailable or untrusted command: {}", cmd);
    }
    #[cfg(unix)]
    {
        let Some(mut command) = trusted_helper_command(cmd) else {
            eprintln!("[!] Refusing unavailable or untrusted command: {}", cmd);
            return;
        };
        match command.args(args).output() {
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
