mod crashlab;
mod model;
mod protocol;

use protocol::render::{check_generated, generate};
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    let result = run_command(env::args().nth(1).as_deref());

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_command(command: Option<&str>) -> Result<(), String> {
    let root = workspace_root()?;
    dispatch_command(command, &root)
}

fn dispatch_command(command: Option<&str>, root: &Path) -> Result<(), String> {
    let mut args = std::env::args().skip(2);
    match command {
        Some("check") => check_all(root),
        Some("check-generated") => check_generated(root),
        Some("generate") => generate(root),
        Some("crashlab") => {
            let sub = args.next().ok_or_else(|| {
                "usage: cargo xtask crashlab <doctor|tier0|tier1|flakey|teardown|help>".to_string()
            })?;
            let rest: Vec<String> = args.collect();
            crashlab::dispatch(root, &sub, &rest)
        }
        _ => Err("usage: cargo xtask <check|check-generated|generate|crashlab ...>".into()),
    }
}

fn workspace_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask manifest has no workspace parent".into())
}

fn check_all(root: &Path) -> Result<(), String> {
    check_target(
        env::consts::ARCH,
        env::consts::OS,
        if cfg!(target_env = "gnu") { "gnu" } else { "" },
        usize::BITS,
    )?;
    check_generated(root)?;
    model::check_model_evidence(root)?;
    for required in [
        "SECURITY.md",
        "CONTRIBUTING.md",
        ".github/CODEOWNERS",
        "docs/compatibility-policy.md",
        "docs/formal-evidence-scope.md",
    ] {
        if !root.join(required).is_file() {
            return Err(format!("required baseline artifact is missing: {required}"));
        }
    }
    Ok(())
}

fn check_target(arch: &str, os: &str, target_env: &str, pointer_width: u32) -> Result<(), String> {
    if (arch, os, target_env, pointer_width) != ("x86_64", "linux", "gnu", 64) {
        return Err(format!(
            "strict prototype target is x86_64-unknown-linux-gnu; got {arch}-{os}-{target_env} ({pointer_width}-bit)"
        ));
    }
    Ok(())
}
