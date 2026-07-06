use std::path::PathBuf;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

pub(super) async fn run_command(
    binary: &str,
    args: &[&str],
    stdin: Option<String>,
) -> Result<(), String> {
    let Some(command_path) = resolve_command(binary) else {
        return Err(format!("{binary} is not available"));
    };
    let mut command = Command::new(command_path);
    command.args(args);
    if stdin.is_some() {
        command.stdin(std::process::Stdio::piped());
    }
    command.stdout(std::process::Stdio::null());
    command.stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|e| format!("spawn {binary} failed: {e}"))?;
    if let Some(blob) = stdin
        && let Some(mut writer) = child.stdin.take()
    {
        writer
            .write_all(blob.as_bytes())
            .await
            .map_err(|e| format!("stdin write {binary} failed: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("wait {binary} failed: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        format!("{binary} exited with status {}", output.status)
    } else {
        stderr
    })
}

pub(super) async fn run_command_stdout(binary: &str, args: &[&str]) -> Result<String, String> {
    let Some(command_path) = resolve_command(binary) else {
        return Err(format!("{binary} is not available"));
    };
    let output = Command::new(command_path)
        .args(args)
        .output()
        .await
        .map_err(|e| format!("wait {binary} failed: {e}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Err(if stderr.is_empty() {
        format!("{binary} exited with status {}", output.status)
    } else {
        stderr
    })
}

fn resolve_command(binary: &str) -> Option<PathBuf> {
    let mut dirs = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    dirs.extend(["/usr/sbin", "/sbin", "/usr/bin", "/bin"].map(PathBuf::from));
    dirs.into_iter()
        .map(|dir| dir.join(binary))
        .find(|candidate| candidate.exists() && candidate.is_file())
}

pub(super) fn has_cap_net_admin() -> bool {
    #[cfg(target_os = "linux")]
    {
        let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
            return false;
        };
        for line in status.lines() {
            if let Some(raw) = line.strip_prefix("CapEff:") {
                let caps = raw.trim();
                if let Ok(bits) = u64::from_str_radix(caps, 16) {
                    const CAP_NET_ADMIN_BIT: u64 = 12;
                    return (bits & (1u64 << CAP_NET_ADMIN_BIT)) != 0;
                }
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}
