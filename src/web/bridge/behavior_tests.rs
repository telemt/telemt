use std::io::Write;
use std::process::{Command, Stdio};

/// Exercises the actual generated page with deterministic network and native-boundary doubles.
pub(super) fn run(page: &super::BridgePage) {
    let mut child = Command::new("node")
        .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src/web/bridge"))
        .args(["-e", include_str!("behavior_tests.js"), "--", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Node.js 22+ is required for executable WEB bridge regressions");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(page.body.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let completed = stdout
        .lines()
        .find_map(|line| line.strip_prefix("telemt-bridge-behavior-complete tests="))
        .and_then(|count| count.parse::<usize>().ok())
        .is_some_and(|count| count > 0);
    assert!(
        output.status.success() && completed,
        "bridge regressions failed:\n{}\n{}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );
}
