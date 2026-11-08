//! Service manager integration for telemt.
//!
//! Supports generating service files for:
//! - systemd (Linux)
//! - OpenRC (Alpine, Gentoo)
//! - rc.d (FreeBSD)

use std::path::Path;

/// Detected init/service system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    /// systemd (most modern Linux distributions)
    Systemd,
    /// OpenRC (Alpine, Gentoo, some BSDs)
    OpenRC,
    /// FreeBSD rc.d
    FreeBSDRc,
    /// No known init system detected
    Unknown,
}

impl std::fmt::Display for InitSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitSystem::Systemd => write!(f, "systemd"),
            InitSystem::OpenRC => write!(f, "OpenRC"),
            InitSystem::FreeBSDRc => write!(f, "FreeBSD rc.d"),
            InitSystem::Unknown => write!(f, "unknown"),
        }
    }
}

/// Detects the init system in use on the current host.
pub fn detect_init_system() -> InitSystem {
    // Check for systemd first (most common on Linux)
    if Path::new("/run/systemd/system").exists() {
        return InitSystem::Systemd;
    }

    // Check for OpenRC
    if Path::new("/sbin/openrc-run").exists() || Path::new("/sbin/openrc").exists() {
        return InitSystem::OpenRC;
    }

    // Check for FreeBSD rc.d
    if Path::new("/etc/rc.subr").exists() && Path::new("/etc/rc.d").exists() {
        return InitSystem::FreeBSDRc;
    }

    // Fallback: check if systemctl exists even without /run/systemd
    if Path::new("/usr/bin/systemctl").exists() || Path::new("/bin/systemctl").exists() {
        return InitSystem::Systemd;
    }

    InitSystem::Unknown
}

/// Returns the default service file path for the given init system.
pub fn service_file_path(init_system: InitSystem) -> &'static str {
    match init_system {
        InitSystem::Systemd => "/etc/systemd/system/telemt.service",
        InitSystem::OpenRC => "/etc/init.d/telemt",
        InitSystem::FreeBSDRc => "/usr/local/etc/rc.d/telemt",
        InitSystem::Unknown => "/etc/init.d/telemt",
    }
}

/// Options for generating service files.
pub struct ServiceOptions<'a> {
    /// Path to the telemt executable
    pub exe_path: &'a Path,
    /// Path to the configuration file
    pub config_path: &'a Path,
    /// User to run as (optional)
    pub user: Option<&'a str>,
    /// Group to run as (optional)
    pub group: Option<&'a str>,
    /// PID file path
    pub pid_file: &'a str,
    /// Working directory
    pub working_dir: Option<&'a str>,
    /// Description
    pub description: &'a str,
}

impl<'a> Default for ServiceOptions<'a> {
    fn default() -> Self {
        Self {
            exe_path: Path::new("/usr/local/bin/telemt"),
            config_path: Path::new("/etc/telemt/config.toml"),
            user: Some("telemt"),
            group: Some("telemt"),
            pid_file: "/var/run/telemt.pid",
            working_dir: Some("/var/lib/telemt"),
            description: "Telemt MTProxy - Telegram MTProto Proxy",
        }
    }
}

/// Generates a service file for the given init system.
pub fn generate_service_file(init_system: InitSystem, opts: &ServiceOptions) -> String {
    match init_system {
        InitSystem::Systemd => generate_systemd_unit(opts),
        InitSystem::OpenRC => generate_openrc_script(opts),
        InitSystem::FreeBSDRc => generate_freebsd_rc_script(opts),
        // Preserve systemd generation when init detection is unavailable.
        InitSystem::Unknown => generate_systemd_unit(opts),
    }
}

/// Generates a hardened systemd unit with Netlink access for optional firewall helpers.
fn generate_systemd_unit(opts: &ServiceOptions) -> String {
    let user_line = opts.user.map(|u| format!("User={}", u)).unwrap_or_default();
    let group_line = opts
        .group
        .map(|g| format!("Group={}", g))
        .unwrap_or_default();
    let working_dir = opts
        .working_dir
        .map(|d| format!("WorkingDirectory={}", d))
        .unwrap_or_default();

    format!(
        r#"[Unit]
Description={description}
Documentation=https://github.com/telemt/telemt
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={exe} --foreground --pid-file {pid_file} {config}
ExecReload=/bin/kill -HUP $MAINPID
PIDFile={pid_file}
Restart=always
RestartSec=5
{user}
{group}
{working_dir}

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true

# Allow privileged port binding, optional firewall helpers, and runtime state writes
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
ReadWritePaths=/etc/telemt /var/run /var/lib/telemt

[Install]
WantedBy=multi-user.target
"#,
        description = opts.description,
        exe = opts.exe_path.display(),
        config = opts.config_path.display(),
        pid_file = opts.pid_file,
        user = user_line,
        group = group_line,
        working_dir = working_dir,
    )
}

/// Generates an OpenRC init script.
fn generate_openrc_script(opts: &ServiceOptions) -> String {
    let user = opts.user.unwrap_or("root");
    let group = opts.group.unwrap_or("root");

    format!(
        r#"#!/sbin/openrc-run
# OpenRC init script for telemt

description="{description}"
command="{exe}"
command_args="--daemon --syslog --pid-file {pid_file} {config}"
command_user="{user}:{group}"
pidfile="{pid_file}"

depend() {{
    need net
    use logger
    after firewall
}}

start_pre() {{
    checkpath --directory --owner {user}:{group} --mode 0755 /var/run
    checkpath --directory --owner {user}:{group} --mode 0755 /var/lib/telemt
    checkpath --directory --owner {user}:{group} --mode 0755 /var/log/telemt
}}

reload() {{
    ebegin "Reloading ${{RC_SVCNAME}}"
    start-stop-daemon --signal HUP --pidfile "${{pidfile}}"
    eend $?
}}
"#,
        description = opts.description,
        exe = opts.exe_path.display(),
        config = opts.config_path.display(),
        pid_file = opts.pid_file,
        user = user,
        group = group,
    )
}

/// Generates a FreeBSD rc.d script.
fn generate_freebsd_rc_script(opts: &ServiceOptions) -> String {
    let user = opts.user.unwrap_or("root");
    let group = opts.group.unwrap_or("");
    // The shared PID default cannot support cleanup after dropping privileges.
    let pid_file = match opts.pid_file {
        "/var/run/telemt.pid" => "/var/run/telemt/telemt.pid",
        path => path,
    };
    let working_dir = match opts.working_dir {
        None | Some("/var/lib/telemt") => "/var/db/telemt",
        Some(path) => path,
    };

    format!(
        r#"#!/bin/sh
#
# PROVIDE: telemt
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown
#
# Add the following lines to /etc/rc.conf to enable telemt:
#
# telemt_enable="YES"
# The configuration path can be overridden in rc.conf.
# telemt_config="/etc/telemt/config.toml"
# The service user and group can be overridden in rc.conf.
# telemt_uid="telemt"
# telemt_gid="telemt"
# Legacy telemt_user/telemt_group settings remain supported as aliases.
# Custom telemt_pidfile parents must already be writable by the service user.
#

. /etc/rc.subr

name="telemt"
rcvar="telemt_enable"
desc="{description}"

load_rc_config $name

: ${{telemt_enable:="NO"}}
: ${{telemt_config:="{config}"}}
: ${{telemt_uid:="${{telemt_user:-{user}}}"}}
: ${{telemt_gid:="${{telemt_group:-{group}}}"}}
: ${{telemt_pidfile:="{pid_file}"}}
: ${{telemt_data_dir:="{working_dir}"}}

# An unspecified group follows the selected account, never an implicit wheel grant.
if [ -z "${{telemt_gid}}" ]; then
    telemt_gid="$(id -gn "${{telemt_uid}}")" || exit 1
fi

# rc.subr must not drop privileges before Telemt binds privileged sockets.
unset telemt_user telemt_group

pidfile="${{telemt_pidfile}}"
command="{exe}"
command_args="--daemon --syslog --working-dir \"${{telemt_data_dir}}\" --pid-file \"${{telemt_pidfile}}\""
# Root startup must retain privileged network setup without a drop request.
if [ "${{telemt_uid}}" != "root" ]; then
    command_args="${{command_args}} --run-as-user \"${{telemt_uid}}\" --run-as-group \"${{telemt_gid}}\""
fi
command_args="${{command_args}} \"${{telemt_config}}\""

start_precmd="telemt_prestart"
reload_cmd="telemt_reload"
extra_commands="reload"

telemt_prestart() {{
    install -d -o "${{telemt_uid}}" -g "${{telemt_gid}}" -m 755 /var/run/telemt || return $?
    install -d -o "${{telemt_uid}}" -g "${{telemt_gid}}" -m 755 "${{telemt_data_dir}}" || return $?
}}

telemt_reload() {{
    if [ -f "${{pidfile}}" ]; then
        echo "Reloading ${{name}} configuration."
        kill -HUP "$(cat "${{pidfile}}")"
    else
        echo "${{name}} is not running."
        return 1
    fi
}}

run_rc_command "$1"
"#,
        description = opts.description,
        exe = opts.exe_path.display(),
        config = opts.config_path.display(),
        pid_file = pid_file,
        working_dir = working_dir,
        user = user,
        group = group,
    )
}

/// Installation instructions for each init system.
pub fn installation_instructions(init_system: InitSystem) -> &'static str {
    match init_system {
        InitSystem::Systemd => {
            r#"To install and enable the service:
  sudo systemctl daemon-reload
  sudo systemctl enable telemt
  sudo systemctl start telemt

To check status:
  sudo systemctl status telemt

To view logs:
  journalctl -u telemt -f

To reload configuration:
  sudo systemctl reload telemt
"#
        }
        InitSystem::OpenRC => {
            r#"To install and enable the service:
  sudo chmod +x /etc/init.d/telemt
  sudo rc-update add telemt default
  sudo rc-service telemt start

To check status:
  sudo rc-service telemt status

To reload configuration:
  sudo rc-service telemt reload
"#
        }
        InitSystem::FreeBSDRc => {
            r#"To install and enable the service:
  sudo chmod +x /usr/local/etc/rc.d/telemt
  sudo sysrc telemt_enable="YES"
  sudo service telemt start

To check status:
  sudo service telemt status

To reload configuration:
  sudo service telemt reload
"#
        }
        InitSystem::Unknown => {
            r#"No supported init system detected.
You may need to create a service file manually or run telemt directly:
  telemt start /etc/telemt/config.toml
"#
        }
    }
}

#[cfg(all(test, unix))]
// Executable shell checks for the generated FreeBSD service lifecycle.
mod freebsd_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemd_unit_generation() {
        let opts = ServiceOptions::default();
        let unit = generate_systemd_unit(&opts);
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("ExecReload="));
        assert!(unit.contains("PIDFile="));
    }

    #[test]
    fn systemd_unit_allows_netlink_without_removing_hardening() {
        let unit = generate_systemd_unit(&ServiceOptions::default());
        let families = unit
            .lines()
            .find_map(|line| line.strip_prefix("RestrictAddressFamilies="))
            .unwrap();
        assert_eq!(
            families.split_whitespace().collect::<Vec<_>>(),
            ["AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK"],
        );
        for directive in [
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "RestrictNamespaces=true",
            "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN",
            "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN",
        ] {
            assert!(unit.lines().any(|line| line == directive), "{directive}");
        }
    }

    #[test]
    fn test_openrc_script_generation() {
        let opts = ServiceOptions::default();
        let script = generate_openrc_script(&opts);
        assert!(script.contains("#!/sbin/openrc-run"));
        assert!(script.contains("depend()"));
        assert!(script.contains("reload()"));
    }

    #[test]
    fn test_freebsd_rc_script_generation() {
        let opts = ServiceOptions::default();
        let script = generate_freebsd_rc_script(&opts);
        assert!(script.contains("#!/bin/sh"));
        assert!(script.contains("PROVIDE: telemt"));
        assert!(script.contains("run_rc_command"));
    }

    #[test]
    fn test_service_file_paths() {
        assert_eq!(
            service_file_path(InitSystem::Systemd),
            "/etc/systemd/system/telemt.service"
        );
        assert_eq!(service_file_path(InitSystem::OpenRC), "/etc/init.d/telemt");
        assert_eq!(
            service_file_path(InitSystem::FreeBSDRc),
            "/usr/local/etc/rc.d/telemt"
        );
    }
}
