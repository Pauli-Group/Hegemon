//! Best-effort startup progress for the local companion window.
//!
//! The file is not chain state. A failed write must not stop the node.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::warn;

pub const NODE_ACTIVITY_FILE: &str = "node-activity.json";

pub const PHASE_OPENING_DATABASE: &str = "opening_database";
pub const PHASE_LOADING_ROWS: &str = "loading_rows";
pub const PHASE_REBUILDING_STATE: &str = "rebuilding_state";
pub const PHASE_RECHECKING_PROOFS: &str = "rechecking_proofs";
pub const PHASE_SAVING_VERIFIED_STATE: &str = "saving_verified_state";
pub const PHASE_CHECKING_INDEXES: &str = "checking_indexes";
pub const PHASE_READY: &str = "ready";

const PHASES: &[&str] = &[
    PHASE_OPENING_DATABASE,
    PHASE_LOADING_ROWS,
    PHASE_REBUILDING_STATE,
    PHASE_RECHECKING_PROOFS,
    PHASE_SAVING_VERIFIED_STATE,
    PHASE_CHECKING_INDEXES,
    PHASE_READY,
];

pub fn publish_node_activity(
    base_path: &Path,
    phase: &str,
    current: Option<u64>,
    total: Option<u64>,
) {
    if let Err(error) = write_node_activity(base_path, phase, current, total) {
        warn!(%error, "native node activity file was not updated");
    }
}

pub fn publish_node_activity_fraction(base_path: &Path, phase: &str, current: u64, total: usize) {
    match u64::try_from(total) {
        Ok(total) if current <= total => {
            publish_node_activity(base_path, phase, Some(current), Some(total));
        }
        _ => publish_node_activity(base_path, phase, None, None),
    }
}

pub fn write_node_activity(
    base_path: &Path,
    phase: &str,
    current: Option<u64>,
    total: Option<u64>,
) -> std::io::Result<()> {
    if !PHASES.contains(&phase) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unknown node activity phase",
        ));
    }
    match (current, total) {
        (None, None) => {}
        (Some(current), Some(total)) if current <= total => {}
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "node activity counters are not a fraction",
            ));
        }
    }
    let body = serde_json::json!({
        "phase": phase,
        "current": current,
        "total": total,
        "updated_at_ms": unix_millis(),
        "pid": std::process::id(),
    });
    let bytes = serde_json::to_vec(&body)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    let destination = base_path.join(NODE_ACTIVITY_FILE);
    let temporary = base_path.join(format!(".{NODE_ACTIVITY_FILE}.tmp"));
    let mut file = File::create(&temporary)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, &destination)?;
    Ok(())
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_file_is_replaced_atomically_and_rejects_a_bad_fraction() {
        let directory = tempfile::tempdir().expect("temp dir");
        write_node_activity(directory.path(), PHASE_OPENING_DATABASE, None, None)
            .expect("first record");
        write_node_activity(
            directory.path(),
            PHASE_RECHECKING_PROOFS,
            Some(14_200),
            Some(15_818),
        )
        .expect("second record");

        let path = directory.path().join(NODE_ACTIVITY_FILE);
        let text = fs::read_to_string(&path).expect("read activity");
        let value: serde_json::Value = serde_json::from_str(&text).expect("json");
        assert_eq!(value["phase"], "rechecking_proofs");
        assert_eq!(value["current"], 14_200);
        assert_eq!(value["total"], 15_818);
        assert_eq!(value["pid"], std::process::id());
        assert!(value["updated_at_ms"].as_u64().is_some());
        assert!(!directory
            .path()
            .join(format!(".{NODE_ACTIVITY_FILE}.tmp"))
            .exists());

        let error = write_node_activity(
            directory.path(),
            PHASE_RECHECKING_PROOFS,
            Some(20),
            Some(10),
        )
        .expect_err("current past total");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        let after = fs::read_to_string(&path).expect("previous record remains");
        assert_eq!(after, text);
    }
}
