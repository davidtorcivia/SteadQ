// Run registry: every tier-1 run registers its resources (backing file, loop
// devices, dm names, mount) before creating them, so `crashlab teardown` can
// recover from a crashed or interrupted run. Plain JSON, single writer.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone)]
pub struct RegistryRun {
    pub id: String,
    pub kind: String,
    pub backing: Option<String>,
    pub marker: Option<String>,
    pub loops: Vec<String>,
    pub dm_names: Vec<String>,
    pub mount: Option<String>,
    #[serde(default)]
    pub pool: Option<String>,
    pub status: String,
    pub started: String,
    pub ended: Option<String>,
}

pub fn registry_path(store: &Path) -> PathBuf {
    store.join("registry.json")
}

pub fn load(store: &Path) -> Vec<RegistryRun> {
    let path = registry_path(store);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

pub fn save(store: &Path, runs: &[RegistryRun]) -> Result<(), String> {
    let path = registry_path(store);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(runs).map_err(|e| format!("serialize registry: {e}"))?,
    )
    .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

pub fn upsert(store: &Path, run: &RegistryRun) -> Result<(), String> {
    let mut runs = load(store);
    match runs.iter_mut().find(|r| r.id == run.id) {
        Some(existing) => *existing = run.clone(),
        None => runs.push(run.clone()),
    }
    save(store, &runs)
}

/// Tear down every active run's resources, name-scoped to this crash lab.
pub fn teardown_active(store: &Path) -> Result<usize, String> {
    let mut runs = load(store);
    let mut torn = 0;
    for run in runs.iter_mut().filter(|r| r.status == "active") {
        eprintln!("tearing down run {}", run.id);
        // A run interrupted mid-cut can leave its device suspended, which
        // blocks umount and remove; resuming an active device is a no-op.
        for dm in &run.dm_names {
            let _ = std::process::Command::new("dmsetup")
                .args(["resume", dm])
                .output();
        }
        if let Some(mount) = &run.mount {
            let _ = std::process::Command::new("umount").arg(mount).output();
        }
        for dm in &run.dm_names {
            let _ = std::process::Command::new("dmsetup")
                .args(["remove", dm])
                .output();
        }
        for loop_dev in &run.loops {
            let _ = std::process::Command::new("losetup")
                .args(["-d", loop_dev])
                .output();
        }
        run.status = "torn-down".into();
        run.ended = Some(super::now_iso());
        torn += 1;
    }
    save(store, &runs)?;
    // Sweep anything the registry missed: mounts and dm tables we own by name.
    sweep_leftovers();
    Ok(torn)
}

fn sweep_leftovers() {
    // Imported crash-lab pools hold their loop devices; export by name
    // prefix before sweeping mounts and dm tables.
    if let Ok(out) = std::process::Command::new("zpool")
        .args(["list", "-Hp", "-o", "name"])
        .output()
    {
        for name in String::from_utf8_lossy(&out.stdout).lines() {
            if name.starts_with("crashl") {
                let _ = std::process::Command::new("zpool")
                    .args(["export", "-f", name])
                    .output();
            }
        }
    }
    if let Ok(out) = std::process::Command::new("findmnt")
        .args(["-rn", "-o", "TARGET"])
        .output()
    {
        for target in String::from_utf8_lossy(&out.stdout).lines() {
            if target.contains("/mnt/crashlab-") {
                let _ = std::process::Command::new("umount").arg(target).output();
            }
        }
    }
    if let Ok(out) = std::process::Command::new("dmsetup").args(["ls"]).output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(name) = line.split_whitespace().next() {
                if name.starts_with("crashlab-") {
                    let _ = std::process::Command::new("dmsetup")
                        .args(["remove", name])
                        .output();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = tmp.path();
        assert!(load(store).is_empty());
        let run = RegistryRun {
            id: "r1".into(),
            kind: "tier1".into(),
            backing: Some("/nvme-mirror/temp/crashlab/r1.img".into()),
            marker: None,
            loops: vec!["/dev/loop7".into()],
            dm_names: vec!["crashlab-r1".into()],
            mount: Some("/mnt/crashlab-r1".into()),
            pool: None,
            status: "active".into(),
            started: "t0".into(),
            ended: None,
        };
        upsert(store, &run).unwrap();
        let loaded = load(store);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, "r1");
        // Upsert updates, not appends.
        let mut done = run.clone();
        done.status = "done".into();
        upsert(store, &done).unwrap();
        assert_eq!(load(store).len(), 1);
        assert_eq!(load(store)[0].status, "done");
    }
}
