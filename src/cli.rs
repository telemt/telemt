//! CLI commands: --init (fire-and-forget setup)

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use rand::Rng;

/// Options for the init command
pub struct InitOptions {
    pub port: u16,
    pub domain: String,
    pub secret: Option<String>,
    pub username: String,
    pub config_dir: PathBuf,
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
    eprintln!("[telemt] Fire-and-forget setup");
    eprintln!();
    
    // 1. Generate or validate secret
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
    
    // 2. Create config directory
    fs::create_dir_all(&opts.config_dir)?;
    let config_path = opts.config_dir.join("config.toml");
    
    // 3. Write config
    let config_content = generate_config(&opts.username, &secret, opts.port, &opts.domain);
    fs::write(&config_path, &config_content)?;
    eprintln!("[+] Config written to {}", config_path.display());
    
    // 4. Write systemd unit
    let exe_path = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("/usr/local/bin/telemt"));
    
    let unit_path = Path::new("/etc/systemd/system/telemt.service");
    let unit_content = generate_systemd_unit(&exe_path, &config_path);
    
    match fs::write(unit_path, &unit_content) {
        Ok(()) => {
            eprintln!("[+] Systemd unit written to {}", unit_path.display());
        }
        Err(e) => {
            eprintln!("[!] Cannot write systemd unit (run as root?): {}", e);
            eprintln!("[!] Manual unit file content:");
            eprintln!("{}", unit_content);
            
            // Still print links and config
            print_links(&opts.username, &secret, opts.port, &opts.domain);
            return Ok(());
        }
    }
    
    // 5. Reload systemd
    run_cmd("systemctl", &["daemon-reload"]);
    
    // 6. Enable service
    run_cmd("systemctl", &["enable", "telemt.service"]);
    eprintln!("[+] Service enabled");
    
    // 7. Start service (unless --no-start)
    if !opts.no_start {
        run_cmd("systemctl", &["start", "telemt.service"]);
        eprintln!("[+] Service started");
        
        // Brief delay then check status
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
    
    eprintln!();
    
    // 8. Print links
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
me_pool_min_fresh_ratio = 0.8
me_reinit_drain_timeout_secs = 120

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
port = {port}
listen_addr_ipv4 = "0.0.0.0"
listen_addr_ipv6 = "::"

[[server.listeners]]
ip = "0.0.0.0"
# reuse_allow = false # Set true only when intentionally running multiple telemt instances on same port

[[server.listeners]]
ip = "::"

[timeouts]
client_handshake = 15
tg_connect = 10
client_keepalive = 60
client_ack = 300

[censorship]
tls_domain = "{domain}"
mask = true
mask_port = 443
fake_cert_len = 2048
tls_full_cert_ttl_secs = 90

[access]
replay_check_len = 65536
replay_window_secs = 1800
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

fn generate_systemd_unit(exe_path: &Path, config_path: &Path) -> String {
    format!(
r#"[Unit]
Description=Telemt MTProxy
Documentation=https://github.com/nicepkg/telemt
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} {config}
Restart=always
RestartSec=5
LimitNOFILE=65535
# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/etc/telemt
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
        exe = exe_path.display(),
        config = config_path.display(),
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
    println!("  EE-TLS:  tg://proxy?server=YOUR_SERVER_IP&port={}&secret=ee{}{}", 
        port, secret, domain_hex);
    println!();
    println!("Replace YOUR_SERVER_IP with your server's public IP.");
    println!("The proxy will auto-detect and display the correct link on startup.");
    println!("Check: journalctl -u telemt.service | head -30");
    println!("===================");
}
