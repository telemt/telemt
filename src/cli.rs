//! CLI commands: --init (fire-and-forget setup)

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use rand::Rng;

// Usernames are limited to the same character set enforced by the API layer.
fn is_valid_cli_username(username: &str) -> bool {
    !username.is_empty()
        && username.len() <= 64
        && username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

// Produces a TOML-safe version of `s` for use inside double-quoted strings
// or as a double-quoted key.  Escapes `\`, `"`, and all ASCII control chars.
fn toml_escape_string_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

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

    if !is_valid_cli_username(&opts.username) {
        return Err(
            "username must be 1..64 chars containing only A-Za-z0-9, '_', '-', '.'".into(),
        );
    }

    // Reject domains with control characters or unreasonable length.
    if opts.domain.is_empty()
        || opts.domain.len() > 253
        || opts.domain.bytes().any(|b| b < 0x20 || b == 0x7f)
    {
        return Err(
            "domain must be a valid hostname (non-empty, max 253 chars, printable ASCII)".into(),
        );
    }

    // 1. Generate or validate secret
    let secret = match opts.secret {
        Some(s) => {
            if s.len() != 32 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("secret must be exactly 32 hex characters".into());
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
    // Escape all values before inserting into the TOML template.
    // Quoted TOML keys ("...") prevent dotted-key interpretation of usernames
    // that contain '.', and escaping prevents injection via '"' or '\'.
    let u = toml_escape_string_value(username);
    let s = toml_escape_string_value(secret);
    let d = toml_escape_string_value(domain);
    format!(
r#"# Telemt MTProxy — auto-generated config
# Re-run `telemt --init` to regenerate

show_link = ["{u}"]

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
tls_domain = "{d}"
mask = true
mask_port = 443
fake_cert_len = 2048
tls_full_cert_ttl_secs = 90

[access]
replay_check_len = 65536
replay_window_secs = 1800
ignore_time_skew = false

[access.users]
"{u}" = "{s}"

[[upstreams]]
type = "direct"
enabled = true
weight = 10
"#,
        u = u,
        s = s,
        d = d,
        port = port,
    )
}

fn generate_systemd_unit(exe_path: &Path, config_path: &Path) -> String {
    // Derive ReadWritePaths from the actual config directory so the service
    // unit grants write access to wherever --config-dir was set, not a
    // hardcoded path that would break non-default installations.
    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("/etc/telemt"));
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
ReadWritePaths={config_dir}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"#,
        exe = exe_path.display(),
        config = config_path.display(),
        config_dir = config_dir.display(),
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

#[cfg(test)]
mod tests {
    use super::{
        generate_config, generate_systemd_unit, is_valid_cli_username, parse_init_args, run_init,
        toml_escape_string_value, InitOptions,
    };

    // ── is_valid_cli_username ────────────────────────────────────────────────

    #[test]
    fn valid_username_alphanumeric_passes() {
        assert!(is_valid_cli_username("alice"));
        assert!(is_valid_cli_username("Alice123"));
        assert!(is_valid_cli_username("a"));
    }

    #[test]
    fn valid_username_with_allowed_punctuation_passes() {
        assert!(is_valid_cli_username("alice.name"));
        assert!(is_valid_cli_username("alice-name"));
        assert!(is_valid_cli_username("alice_name"));
    }

    #[test]
    fn valid_username_at_max_length_passes() {
        assert!(is_valid_cli_username(&"a".repeat(64)));
    }

    #[test]
    fn empty_username_fails() {
        assert!(!is_valid_cli_username(""));
    }

    #[test]
    fn username_over_64_chars_fails() {
        assert!(!is_valid_cli_username(&"a".repeat(65)));
    }

    #[test]
    fn username_with_space_fails() {
        assert!(!is_valid_cli_username("alice bob"));
    }

    #[test]
    fn username_with_quote_fails() {
        assert!(!is_valid_cli_username("alice\"name"));
    }

    #[test]
    fn username_with_newline_fails() {
        assert!(!is_valid_cli_username("alice\nname"));
    }

    #[test]
    fn username_with_slash_fails() {
        assert!(!is_valid_cli_username("alice/name"));
    }

    #[test]
    fn username_with_at_sign_fails() {
        assert!(!is_valid_cli_username("alice@example.com"));
    }

    // ── toml_escape_string_value ─────────────────────────────────────────────

    #[test]
    fn escape_plain_string_returns_unchanged() {
        assert_eq!(toml_escape_string_value("hello"), "hello");
        assert_eq!(toml_escape_string_value("alice.name"), "alice.name");
        assert_eq!(toml_escape_string_value("www.google.com"), "www.google.com");
    }

    #[test]
    fn escape_double_quote() {
        assert_eq!(toml_escape_string_value(r#"a"b"#), r#"a\"b"#);
    }

    #[test]
    fn escape_backslash() {
        assert_eq!(toml_escape_string_value(r"a\b"), r"a\\b");
    }

    #[test]
    fn escape_newline() {
        assert_eq!(toml_escape_string_value("a\nb"), "a\\nb");
    }

    #[test]
    fn escape_carriage_return() {
        assert_eq!(toml_escape_string_value("a\rb"), "a\\rb");
    }

    #[test]
    fn escape_tab() {
        assert_eq!(toml_escape_string_value("a\tb"), "a\\tb");
    }

    #[test]
    fn escape_null_byte_as_unicode_escape() {
        assert_eq!(toml_escape_string_value("a\x00b"), "a\\u0000b");
    }

    #[test]
    fn escape_arbitrary_control_char_as_unicode_escape() {
        // ASCII 0x01 (SOH) must become \u0001
        assert_eq!(toml_escape_string_value("a\x01b"), "a\\u0001b");
    }

    #[test]
    fn escape_combined_injection_attempt() {
        // Attacker tries to close the TOML string and inject new keys.
        // Verify the escaped value round-trips through TOML parsing with its
        // original contents intact — the injection attempt must be neutralised.
        let input = r#"evil" \n[inject]"#;
        let escaped = toml_escape_string_value(input);
        let toml_str = format!("x = \"{escaped}\"");
        let parsed: toml::Value =
            toml::from_str(&toml_str).expect("escaped injection attempt must be valid TOML");
        let value = parsed.get("x").and_then(|v| v.as_str()).unwrap();
        assert_eq!(value, input, "value must round-trip unchanged after escaping");
    }

    // ── generate_config ──────────────────────────────────────────────────────

    const VALID_SECRET: &str = "abcdef0123456789abcdef0123456789";

    fn parse_toml(content: &str) -> toml::Value {
        toml::from_str(content).expect("generated config must be valid TOML")
    }

    #[test]
    fn generate_config_baseline_produces_valid_toml() {
        let content = generate_config("alice", VALID_SECRET, 443, "www.google.com");
        let _parsed = parse_toml(&content);
    }

    #[test]
    fn generate_config_username_with_dot_produces_valid_toml() {
        // A username with '.' must be treated as a quoted TOML key, not as a
        // dotted-key sequence that would create a nested table.
        let content = generate_config("user.name", VALID_SECRET, 443, "www.google.com");
        let parsed = parse_toml(&content);
        let secret = parsed
            .get("access")
            .and_then(|a| a.get("users"))
            .and_then(|u| u.as_table())
            .and_then(|t| t.get("user.name"))
            .and_then(|v| v.as_str());
        assert_eq!(
            secret,
            Some(VALID_SECRET),
            "username with '.' must be stored as a literal key, not a dotted path"
        );
    }

    #[test]
    fn generate_config_domain_with_double_quote_produces_valid_toml() {
        // Injection attempt: close the TOML string, inject extra keys.
        let evil_domain = "evil.com\" \n[injected_section]";
        let content = generate_config("alice", VALID_SECRET, 443, evil_domain);
        let parsed = parse_toml(&content);
        let domain = parsed
            .get("censorship")
            .and_then(|c| c.get("tls_domain"))
            .and_then(|d| d.as_str());
        assert_eq!(domain, Some(evil_domain));
        // The injected section name must not appear as a top-level table.
        assert!(parsed.get("injected_section").is_none());
    }

    #[test]
    fn generate_config_domain_with_backslash_produces_valid_toml() {
        let content = generate_config("alice", VALID_SECRET, 443, "evil\\domain");
        let parsed = parse_toml(&content);
        let domain = parsed
            .get("censorship")
            .and_then(|c| c.get("tls_domain"))
            .and_then(|d| d.as_str());
        assert_eq!(domain, Some("evil\\domain"));
    }

    #[test]
    fn generate_config_username_with_double_quote_produces_valid_toml() {
        let content = generate_config("user\"name", VALID_SECRET, 443, "www.example.com");
        let parsed = parse_toml(&content);
        let users = parsed
            .get("access")
            .and_then(|a| a.get("users"))
            .and_then(|u| u.as_table());
        assert!(users.is_some());
        // Key must be "user\"name" (the literal string with a quote)
        assert!(users.unwrap().contains_key("user\"name"));
    }

    #[test]
    fn generate_config_show_link_username_survives_round_trip() {
        // The username must also be faithfully preserved in show_link.
        let content = generate_config("alice", VALID_SECRET, 443, "www.google.com");
        let parsed = parse_toml(&content);
        let show_link = parsed
            .get("show_link")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str());
        assert_eq!(show_link, Some("alice"));
    }

    #[test]
    fn generate_config_port_is_set_correctly() {
        let content = generate_config("alice", VALID_SECRET, 8443, "www.google.com");
        let parsed = parse_toml(&content);
        let port = parsed
            .get("server")
            .and_then(|s| s.get("port"))
            .and_then(|p| p.as_integer());
        assert_eq!(port, Some(8443));
    }

    // ── parse_init_args ──────────────────────────────────────────────────────

    #[test]
    fn parse_init_args_without_flag_returns_none() {
        let args = vec!["telemt".to_string(), "--config".to_string()];
        assert!(parse_init_args(&args).is_none());
    }

    #[test]
    fn parse_init_args_with_flag_returns_some_with_defaults() {
        let args = vec!["telemt".to_string(), "--init".to_string()];
        let opts = parse_init_args(&args).expect("must return Some when --init is present");
        assert_eq!(opts.port, 443);
        assert_eq!(opts.domain, "www.google.com");
        assert_eq!(opts.username, "user");
        assert!(opts.secret.is_none());
        assert!(!opts.no_start);
    }

    #[test]
    fn parse_init_args_reads_all_named_flags() {
        let args = [
            "telemt", "--init",
            "--port", "8443",
            "--domain", "example.com",
            "--secret", "deadbeefdeadbeefdeadbeefdeadbeef",
            "--user", "bob",
            "--no-start",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();

        let opts = parse_init_args(&args).unwrap();
        assert_eq!(opts.port, 8443);
        assert_eq!(opts.domain, "example.com");
        assert_eq!(opts.secret.as_deref(), Some("deadbeefdeadbeefdeadbeefdeadbeef"));
        assert_eq!(opts.username, "bob");
        assert!(opts.no_start);
    }

    #[test]
    fn parse_init_args_config_dir_is_set() {
        let args = ["telemt", "--init", "--config-dir", "/tmp/myconf"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let opts = parse_init_args(&args).unwrap();
        assert_eq!(opts.config_dir.to_str(), Some("/tmp/myconf"));
    }

    #[test]
    fn parse_init_args_invalid_port_falls_back_to_443() {
        let args = ["telemt", "--init", "--port", "not-a-number"]
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let opts = parse_init_args(&args).unwrap();
        // unwrap_or(443) means invalid port silently becomes default
        assert_eq!(opts.port, 443);
    }

    // ── run_init input validation ────────────────────────────────────────────

    #[test]
    fn run_init_rejects_empty_username() {
        let opts = InitOptions {
            username: "".to_string(),
            ..InitOptions::default()
        };
        let result = run_init(opts);
        assert!(result.is_err(), "empty username must be rejected");
    }

    #[test]
    fn run_init_rejects_username_with_space() {
        let opts = InitOptions {
            username: "bad user".to_string(),
            ..InitOptions::default()
        };
        assert!(run_init(opts).is_err());
    }

    #[test]
    fn run_init_rejects_username_with_injection_chars() {
        for bad in &[
            "user\"name",
            "user\nname",
            "user\0name",
            "u/path",
            "alice@evil",
        ] {
            let opts = InitOptions {
                username: bad.to_string(),
                ..InitOptions::default()
            };
            assert!(
                run_init(opts).is_err(),
                "username {:?} must be rejected",
                bad
            );
        }
    }

    #[test]
    fn run_init_rejects_invalid_secret() {
        let opts = InitOptions {
            secret: Some("tooshort".to_string()),
            ..InitOptions::default()
        };
        assert!(run_init(opts).is_err());
    }

    #[test]
    fn run_init_rejects_secret_with_non_hex_chars() {
        let opts = InitOptions {
            secret: Some("gggggggggggggggggggggggggggggggg".to_string()),
            ..InitOptions::default()
        };
        assert!(run_init(opts).is_err());
    }

    #[test]
    fn run_init_rejects_empty_domain() {
        let opts = InitOptions {
            domain: "".to_string(),
            ..InitOptions::default()
        };
        assert!(run_init(opts).is_err());
    }

    #[test]
    fn run_init_rejects_domain_with_newline() {
        let opts = InitOptions {
            domain: "evil.com\n[injected]".to_string(),
            ..InitOptions::default()
        };
        assert!(run_init(opts).is_err());
    }

    #[test]
    fn run_init_rejects_domain_with_null_byte() {
        let opts = InitOptions {
            domain: "evil.com\x00extra".to_string(),
            ..InitOptions::default()
        };
        assert!(run_init(opts).is_err());
    }

    #[test]
    fn run_init_rejects_domain_exceeding_253_chars() {
        let opts = InitOptions {
            domain: "a".repeat(254),
            ..InitOptions::default()
        };
        assert!(run_init(opts).is_err());
    }

    // ── generate_systemd_unit ────────────────────────────────────────────────

    #[test]
    fn generate_systemd_unit_uses_config_file_parent_as_read_write_path() {
        use std::path::Path;
        let unit = generate_systemd_unit(
            Path::new("/usr/local/bin/telemt"),
            Path::new("/opt/myproxy/config.toml"),
        );
        assert!(
            unit.contains("ReadWritePaths=/opt/myproxy"),
            "ReadWritePaths must be the config file's actual parent directory"
        );
        assert!(
            !unit.contains("ReadWritePaths=/etc/telemt"),
            "ReadWritePaths must not be hardcoded when a different config dir is used"
        );
    }

    #[test]
    fn generate_systemd_unit_defaults_to_etc_telemt_for_standard_install() {
        use std::path::Path;
        let unit = generate_systemd_unit(
            Path::new("/usr/local/bin/telemt"),
            Path::new("/etc/telemt/config.toml"),
        );
        assert!(unit.contains("ReadWritePaths=/etc/telemt"));
    }

    #[test]
    fn generate_systemd_unit_exec_start_references_correct_exe_and_config() {
        use std::path::Path;
        let unit = generate_systemd_unit(
            Path::new("/usr/bin/telemt"),
            Path::new("/var/lib/telemt/config.toml"),
        );
        assert!(unit.contains("ExecStart=/usr/bin/telemt /var/lib/telemt/config.toml"));
    }

    #[test]
    fn generate_systemd_unit_nested_config_dir_is_reflected_in_read_write_paths() {
        use std::path::Path;
        let unit = generate_systemd_unit(
            Path::new("/usr/local/bin/telemt"),
            Path::new("/srv/proxy/conf/config.toml"),
        );
        assert!(unit.contains("ReadWritePaths=/srv/proxy/conf"));
        assert!(!unit.contains("ReadWritePaths=/etc/telemt"));
    }

    // ── domain validation edge cases ─────────────────────────────────────────

    // DEL character (0x7F) is not a valid hostname byte and must be rejected,
    // analogous to other control characters below 0x20.
    #[test]
    fn run_init_rejects_domain_with_del_char() {
        let opts = InitOptions {
            domain: "evil.com\x7f".to_string(),
            ..InitOptions::default()
        };
        assert!(run_init(opts).is_err(), "domain with DEL (0x7F) must be rejected");
    }

    // A domain of exactly 253 characters must pass validation (the maximum
    // allowed length for a DNS fully-qualified domain name).
    #[test]
    fn run_init_accepts_domain_at_exactly_max_length_of_253_chars() {
        // 249 'a' + ".com" = 253
        let domain = format!("{}.com", "a".repeat(249));
        assert_eq!(domain.len(), 253);
        let is_rejected = domain.is_empty()
            || domain.len() > 253
            || domain.bytes().any(|b| b < 0x20 || b == 0x7f);
        assert!(!is_rejected, "domain of exactly 253 chars must pass the length gate");
    }

    // ── toml_escape_string_value extended control-char coverage ──────────────

    // DEL (0x7F) is a control character and must become \\u007F.
    #[test]
    fn toml_escape_string_value_escapes_del_char() {
        assert_eq!(toml_escape_string_value("\x7f"), "\\u007F");
    }

    // SOH (0x01) is a control character not covered by the named escapes and
    // must fall through to the \\uXXXX path.
    #[test]
    fn toml_escape_string_value_escapes_soh_as_unicode_escape() {
        assert_eq!(toml_escape_string_value("\x01"), "\\u0001");
    }

    // Unit separator (0x1F) is the last control character before 0x20 and
    // must be unicode-escaped.
    #[test]
    fn toml_escape_string_value_escapes_unit_separator() {
        assert_eq!(toml_escape_string_value("\x1f"), "\\u001F");
    }

    // Adversarial: injection attempt combining multiple escape-triggering chars
    // must round-trip through TOML parsing with the original content intact.
    #[test]
    fn toml_escape_string_value_combined_control_char_injection_is_neutralized() {
        let input = "\x00evil\x01\x1f\x7f";
        let escaped = toml_escape_string_value(input);
        let toml_str = format!("x = \"{escaped}\"");
        let parsed: toml::Value =
            toml::from_str(&toml_str).expect("escaped value must produce valid TOML");
        let value = parsed.get("x").and_then(|v| v.as_str()).unwrap();
        assert_eq!(value, input, "value must survive the escape / parse round-trip");
    }

    // Ensure is_valid_cli_username rejects usernames containing a null byte,
    // which would otherwise appear invisible in log output.
    #[test]
    fn username_with_null_byte_fails_validation() {
        assert!(!is_valid_cli_username("user\x00name"));
    }
}
