use super::*;
use std::io::Write;
use std::process::{Command, Stdio};

// Replace rc.subr and privileged commands, but execute the generated shell itself.
fn run_script(opts: &ServiceOptions, config: &str, fail_install: bool) -> std::process::Output {
    let harness = format!(
        r#"
load_rc_config() {{
    :
{config}
}}
id() {{
    printf '%s_primary\n' "$2"
}}
install() {{
    printf 'install'
    printf ' <%s>' "$@"
    printf '\n'
    {install_result}
}}
run_rc_command() {{
    printf 'rc-user=<%s> rc-group=<%s>\n' "${{telemt_user-unset}}" "${{telemt_group-unset}}"
    "$start_precmd" || return $?
    printf 'pid=<%s>\n' "$pidfile"
    eval "set -- $command_args"
    printf 'arg=<%s>\n' "$@"
}}
"#,
        install_result = if fail_install {
            "return 19"
        } else {
            "return 0"
        },
    );
    let script = generate_freebsd_rc_script(opts).replace(". /etc/rc.subr", &harness);
    let mut child = Command::new("/bin/sh")
        .arg("-s")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(script.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn freebsd_default_owns_only_service_directories_and_drops_privileges_internally() {
    let output = run_script(&ServiceOptions::default(), "", false);
    assert!(output.status.success(), "{:?}", output);
    let text = String::from_utf8(output.stdout).unwrap();
    let installs: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("install "))
        .collect();
    assert_eq!(
        installs,
        [
            "install <-d> <-o> <telemt> <-g> <telemt> <-m> <755> </var/run/telemt>",
            "install <-d> <-o> <telemt> <-g> <telemt> <-m> <755> </var/db/telemt>",
        ]
    );
    assert!(text.contains("rc-user=<unset> rc-group=<unset>"));
    assert!(text.contains("pid=</var/run/telemt/telemt.pid>"));
    assert!(text.contains("arg=<--run-as-user>\narg=<telemt>"));
    assert!(text.contains("arg=<--run-as-group>\narg=<telemt>"));
    assert!(text.contains("arg=<--working-dir>\narg=</var/db/telemt>"));
}

#[test]
fn freebsd_legacy_identity_settings_use_internal_privilege_drop() {
    let output = run_script(
        &ServiceOptions::default(),
        "telemt_user=legacy\ntelemt_group=legacygroup",
        false,
    );
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("rc-user=<unset> rc-group=<unset>"));
    assert!(text.contains("arg=<--run-as-user>\narg=<legacy>"));
    assert!(text.contains("arg=<--run-as-group>\narg=<legacygroup>"));
}

#[test]
fn freebsd_new_identity_settings_override_legacy_aliases() {
    let output = run_script(
        &ServiceOptions::default(),
        "telemt_user=legacy\ntelemt_group=legacygroup\ntelemt_uid=newuser\ntelemt_gid=newgroup",
        false,
    );
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("arg=<--run-as-user>\narg=<newuser>"));
    assert!(text.contains("arg=<--run-as-group>\narg=<newgroup>"));
    assert!(!text.contains("legacy"));
}

#[test]
fn freebsd_root_start_preserves_privileged_network_initialization() {
    let opts = ServiceOptions {
        user: None,
        group: None,
        ..Default::default()
    };
    let output = run_script(&opts, "", false);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains("arg=<--run-as-"));
    assert!(text.contains("rc-user=<unset> rc-group=<unset>"));
}

#[test]
fn freebsd_user_override_without_group_uses_the_accounts_primary_group() {
    let opts = ServiceOptions {
        user: None,
        group: None,
        ..Default::default()
    };
    for config in ["telemt_user=legacy", "telemt_uid=legacy"] {
        let output = run_script(&opts, config, false);
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.contains("arg=<--run-as-group>\narg=<legacy_primary>"));
        assert!(text.contains("<-g> <legacy_primary>"));
        assert!(!text.contains("wheel"));
    }
}

#[test]
fn freebsd_custom_paths_are_preserved_without_chowning_the_pid_parent() {
    let opts = ServiceOptions {
        pid_file: "/custom run/proxy.pid",
        working_dir: Some("/custom data/telemt"),
        config_path: Path::new("/custom config/telemt.toml"),
        ..Default::default()
    };
    let output = run_script(&opts, "", false);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("pid=</custom run/proxy.pid>"));
    assert!(text.contains("arg=</custom run/proxy.pid>"));
    assert!(text.contains("arg=</custom data/telemt>"));
    assert!(text.contains("arg=</custom config/telemt.toml>"));
    assert!(
        !text
            .lines()
            .any(|line| line.starts_with("install ") && line.ends_with("</custom run>"))
    );
}

#[test]
fn freebsd_rc_conf_pid_override_does_not_change_shared_directory_ownership() {
    let output = run_script(
        &ServiceOptions::default(),
        "telemt_pidfile=/var/run/custom.pid",
        false,
    );
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("pid=</var/run/custom.pid>"));
    assert!(
        !text
            .lines()
            .any(|line| line.starts_with("install ") && line.ends_with("</var/run>"))
    );
}

#[test]
fn freebsd_directory_setup_failure_aborts_startup() {
    let output = run_script(&ServiceOptions::default(), "", true);
    assert_eq!(output.status.code(), Some(19));
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        text.lines()
            .filter(|line| line.starts_with("install "))
            .count(),
        1
    );
    assert!(!text.contains("arg="));
}
