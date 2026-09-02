// Seeded in-memory filesystem simulator and trace event schema.
//
// Models both file-data durability and directory-entry durability.
// crash() restores the durable namespace: only paths whose parent directory
// has been fsynced (committing the entry) and whose file data has been
// fsynced (for file contents) survive.

use std::collections::{HashMap, HashSet};

/// Seeded pseudo-random number generator for deterministic simulation.
#[derive(Clone, Debug)]
pub struct Rng {
    state: u64,
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        // xorshift has a fixed point at zero, so seed 0 must not be stored as is.
        Rng { state: seed.max(1) }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;
        self.state
    }

    pub fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }

    pub fn next_range(&mut self, max: u64) -> u64 {
        if max == 0 {
            return 0;
        }
        self.next_u64() % max
    }
}

/// A simulated file in the volatile namespace.
#[derive(Clone, Debug)]
pub struct SimFile {
    pub content: Vec<u8>,
    /// True when the current content has been fsynced.
    pub data_synced: bool,
}

/// Durable snapshot of a file that survives crash.
#[derive(Clone, Debug)]
struct DurableFile {
    content: Vec<u8>,
}

/// Seeded in-memory filesystem simulator with directory-entry durability.
///
/// Volatile maps are the live tree. Durable maps are the last committed
/// namespace (via fsync_dir of the parent) and last synced file contents
/// (via fsync_file). crash() replaces the volatile tree with the durable one.
#[derive(Clone, Debug)]
pub struct Simulator {
    /// Live files keyed by normalized path.
    files: HashMap<String, SimFile>,
    /// Live directories keyed by normalized path (empty string = root).
    dirs: HashSet<String>,
    /// Directory entries that have been committed by fsync_dir of their parent.
    durable_entries: HashSet<String>,
    /// File contents last committed by fsync_file, keyed by path.
    durable_file_data: HashMap<String, DurableFile>,
    /// Directories present in the durable namespace.
    durable_dirs: HashSet<String>,
    rng: Rng,
}

impl Simulator {
    pub fn new(seed: u64) -> Self {
        let mut dirs = HashSet::new();
        dirs.insert(String::new()); // root
        let mut durable_dirs = HashSet::new();
        durable_dirs.insert(String::new());
        // Root entry is durable from the start.
        let mut durable_entries = HashSet::new();
        durable_entries.insert(String::new());
        Simulator {
            files: HashMap::new(),
            dirs,
            durable_entries,
            durable_file_data: HashMap::new(),
            durable_dirs,
            rng: Rng::new(seed),
        }
    }

    pub fn create_dir(&mut self, path: &str) {
        let path = normalize_path(path);
        // Ensure ancestors exist in the volatile tree.
        self.ensure_volatile_ancestors(&path);
        self.dirs.insert(path);
    }

    pub fn write_file(&mut self, path: &str, content: Vec<u8>) {
        let path = normalize_path(path);
        self.ensure_volatile_ancestors(&path);
        self.files.insert(
            path,
            SimFile {
                content,
                data_synced: false,
            },
        );
    }

    pub fn fsync_file(&mut self, path: &str) {
        let path = normalize_path(path);
        if let Some(f) = self.files.get_mut(&path) {
            f.data_synced = true;
            self.durable_file_data.insert(
                path,
                DurableFile {
                    content: f.content.clone(),
                },
            );
        }
    }

    /// Commit the current children of `path` into the durable namespace.
    ///
    /// After this returns, every name present under `path` in the volatile
    /// tree is durable, and every name that was durable under `path` but is
    /// no longer present is removed from the durable namespace.
    pub fn fsync_dir(&mut self, path: &str) {
        let path = normalize_path(path);
        if !self.dirs.contains(&path) {
            return;
        }
        self.durable_dirs.insert(path.clone());
        self.durable_entries.insert(path.clone());

        // Collect current children of this directory.
        let mut live_children: HashSet<String> = HashSet::new();
        for d in &self.dirs {
            if parent_of(d).as_deref() == Some(path.as_str()) {
                live_children.insert(d.clone());
            }
        }
        for f in self.files.keys() {
            if parent_of(f).as_deref() == Some(path.as_str()) {
                live_children.insert(f.clone());
            }
        }

        // Drop durable children of this parent that are no longer live.
        let stale: Vec<String> = self
            .durable_entries
            .iter()
            .filter(|e| parent_of(e).as_deref() == Some(path.as_str()))
            .cloned()
            .collect();
        for e in stale {
            if !live_children.contains(&e) {
                self.durable_entries.remove(&e);
                self.durable_dirs.remove(&e);
                self.durable_file_data.remove(&e);
                // Also drop durable descendants of a removed directory entry.
                self.drop_durable_descendants(&e);
            }
        }

        // Commit live children as durable entries. File data is only
        // durable when it has also been fsynced.
        for child in live_children {
            self.durable_entries.insert(child.clone());
            if self.dirs.contains(&child) {
                self.durable_dirs.insert(child);
            } else if let Some(f) = self.files.get(&child) {
                if f.data_synced {
                    self.durable_file_data.insert(
                        child,
                        DurableFile {
                            content: f.content.clone(),
                        },
                    );
                }
            }
        }
    }

    pub fn rename_noreplace(&mut self, src: &str, dest: &str) -> Result<(), SimError> {
        let src = normalize_path(src);
        let dest = normalize_path(dest);
        if self.files.contains_key(&dest) || self.dirs.contains(&dest) {
            return Err(SimError::AlreadyExists);
        }
        match self.files.remove(&src) {
            Some(entry) => {
                self.ensure_volatile_ancestors(&dest);
                self.files.insert(dest, entry);
                // Source name is gone from volatile; dest name is new and
                // not durable until the parent directories are fsynced.
                Ok(())
            }
            None => Err(SimError::NotFound),
        }
    }

    pub fn unlink(&mut self, path: &str) -> Result<(), SimError> {
        let path = normalize_path(path);
        if self.files.remove(&path).is_some() {
            Ok(())
        } else {
            Err(SimError::NotFound)
        }
    }

    /// Simulate a crash: restore the durable namespace.
    ///
    /// Surviving files must have a durable directory entry and durable data.
    /// Unsynced directory renames/creates/deletes are rolled back.
    pub fn crash(&mut self) {
        let mut files = HashMap::new();
        for path in &self.durable_entries {
            if let Some(data) = self.durable_file_data.get(path) {
                files.insert(
                    path.clone(),
                    SimFile {
                        content: data.content.clone(),
                        data_synced: true,
                    },
                );
            }
        }
        self.files = files;
        self.dirs = self.durable_dirs.clone();
        // Ensure root always exists.
        self.dirs.insert(String::new());
        self.durable_dirs.insert(String::new());
        self.durable_entries.insert(String::new());
    }

    pub fn exists(&self, path: &str) -> bool {
        let path = normalize_path(path);
        self.files.contains_key(&path) || self.dirs.contains(&path)
    }

    /// True if the path has a durable directory entry.
    pub fn entry_is_durable(&self, path: &str) -> bool {
        let path = normalize_path(path);
        self.durable_entries.contains(&path)
    }

    pub fn read_file(&self, path: &str) -> Option<&[u8]> {
        let path = normalize_path(path);
        self.files.get(&path).map(|f| f.content.as_slice())
    }

    pub fn maybe_inject_fault(&mut self, probability: u64) -> bool {
        self.rng.next_range(100) < probability
    }

    fn ensure_volatile_ancestors(&mut self, path: &str) {
        let mut acc = String::new();
        for part in path.split('/').filter(|s| !s.is_empty()) {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            // Only create intermediate dirs for the path's parents, not the
            // final component (which may be a file).
            if acc != path {
                self.dirs.insert(acc.clone());
            }
        }
        // Parent of path
        if let Some(parent) = parent_of(path) {
            self.dirs.insert(parent);
        }
    }

    fn drop_durable_descendants(&mut self, prefix: &str) {
        let prefix_slash = if prefix.is_empty() {
            String::new()
        } else {
            format!("{prefix}/")
        };
        let doomed: Vec<String> = self
            .durable_entries
            .iter()
            .filter(|e| !prefix_slash.is_empty() && e.starts_with(&prefix_slash))
            .cloned()
            .collect();
        for e in doomed {
            self.durable_entries.remove(&e);
            self.durable_dirs.remove(&e);
            self.durable_file_data.remove(&e);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimError {
    NotFound,
    AlreadyExists,
}

fn normalize_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    parts.join("/")
}

fn parent_of(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    match path.rfind('/') {
        Some(i) => Some(path[..i].to_string()),
        None => Some(String::new()), // child of root
    }
}

/// Trace event schema (versioned).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TraceEvent {
    pub schema_version: u32,
    pub operation_id: u64,
    pub job_id_hex: String,
    pub source_state: Option<String>,
    pub destination_state: Option<String>,
    pub pre_generation: Option<u64>,
    pub post_generation: Option<u64>,
    pub attempt: Option<u32>,
    pub syscall_result: Option<String>,
    pub sync_result: Option<String>,
    pub fault_point: Option<String>,
}

impl TraceEvent {
    pub fn schema_version() -> u32 {
        1
    }

    pub fn new(operation_id: u64) -> Self {
        TraceEvent {
            schema_version: Self::schema_version(),
            operation_id,
            job_id_hex: String::new(),
            source_state: None,
            destination_state: None,
            pre_generation: None,
            post_generation: None,
            attempt: None,
            syscall_result: None,
            sync_result: None,
            fault_point: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != Self::schema_version() {
            return Err(format!(
                "schema version mismatch: expected {}, got {}",
                Self::schema_version(),
                self.schema_version
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulator_crash_removes_unsynced() {
        let mut sim = Simulator::new(42);
        sim.create_dir("ready/0000");
        sim.write_file("ready/0000/job.sqj", vec![0xAB; 128]);
        assert!(sim.exists("ready/0000/job.sqj"));
        sim.crash();
        assert!(!sim.exists("ready/0000/job.sqj"));
    }

    #[test]
    fn simulator_crash_preserves_synced_with_dir_fsync() {
        let mut sim = Simulator::new(42);
        sim.create_dir("ready/0000");
        sim.fsync_dir(""); // commit ready ancestor chain step by step
        sim.fsync_dir("ready");
        sim.fsync_dir("ready/0000");
        sim.write_file("ready/0000/job.sqj", vec![0xAB; 128]);
        sim.fsync_file("ready/0000/job.sqj");
        sim.fsync_dir("ready/0000");
        sim.crash();
        assert!(sim.exists("ready/0000/job.sqj"));
    }

    #[test]
    fn simulator_file_sync_without_dir_sync_is_lost() {
        // Data fsync alone is not enough; the directory entry must also be durable.
        let mut sim = Simulator::new(42);
        sim.create_dir("ready/0000");
        sim.write_file("ready/0000/job.sqj", vec![0xAB; 128]);
        sim.fsync_file("ready/0000/job.sqj");
        // No fsync_dir of ready/0000
        sim.crash();
        assert!(!sim.exists("ready/0000/job.sqj"));
        assert!(!sim.entry_is_durable("ready/0000/job.sqj"));
    }

    #[test]
    fn simulator_rename_without_dest_dir_sync_rolls_back() {
        let mut sim = Simulator::new(42);
        sim.create_dir("ready/0000");
        sim.create_dir("leased/boot/0/0000");
        sim.write_file("ready/0000/job.sqj", vec![0x42; 128]);
        sim.fsync_file("ready/0000/job.sqj");
        sim.fsync_dir("ready");
        sim.fsync_dir("ready/0000");
        // File is durable under ready/0000
        sim.rename_noreplace("ready/0000/job.sqj", "leased/boot/0/0000/job.sqj")
            .unwrap();
        // Dest dir not fsynced; source dir not fsynced after remove.
        sim.crash();
        // Durable namespace still has the pre-rename entry.
        assert!(sim.exists("ready/0000/job.sqj"));
        assert!(!sim.exists("leased/boot/0/0000/job.sqj"));
    }

    #[test]
    fn simulator_rename_with_both_dir_syncs_is_durable() {
        let mut sim = Simulator::new(42);
        sim.create_dir("ready/0000");
        sim.create_dir("leased/boot/0/0000");
        sim.write_file("ready/0000/job.sqj", vec![0x42; 128]);
        sim.fsync_file("ready/0000/job.sqj");
        sim.fsync_dir("ready");
        sim.fsync_dir("ready/0000");
        sim.rename_noreplace("ready/0000/job.sqj", "leased/boot/0/0000/job.sqj")
            .unwrap();
        sim.fsync_dir("leased");
        sim.fsync_dir("leased/boot");
        sim.fsync_dir("leased/boot/0");
        sim.fsync_dir("leased/boot/0/0000");
        sim.fsync_dir("ready/0000"); // commit source removal
        sim.crash();
        assert!(!sim.exists("ready/0000/job.sqj"));
        assert!(sim.exists("leased/boot/0/0000/job.sqj"));
    }

    #[test]
    fn simulator_rename_noreplace() {
        let mut sim = Simulator::new(42);
        sim.create_dir("ready/0000");
        sim.create_dir("leased/boot/0/0000");
        sim.write_file("ready/0000/job.sqj", vec![0x42; 128]);
        sim.fsync_file("ready/0000/job.sqj");

        sim.rename_noreplace("ready/0000/job.sqj", "leased/boot/0/0000/job.sqj")
            .unwrap();
        assert!(!sim.exists("ready/0000/job.sqj"));
        assert!(sim.exists("leased/boot/0/0000/job.sqj"));
    }

    #[test]
    fn simulator_rename_rejects_collision() {
        let mut sim = Simulator::new(42);
        sim.create_dir("ready/0000");
        sim.write_file("ready/0000/a.sqj", vec![0x42; 128]);
        sim.write_file("ready/0000/b.sqj", vec![0x43; 128]);
        assert_eq!(
            sim.rename_noreplace("ready/0000/a.sqj", "ready/0000/b.sqj"),
            Err(SimError::AlreadyExists)
        );
    }

    #[test]
    fn rng_deterministic() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn trace_event_validation() {
        let event = TraceEvent::new(1);
        assert!(event.validate().is_ok());

        let mut bad = event;
        bad.schema_version = 999;
        assert!(bad.validate().is_err());
    }
}
