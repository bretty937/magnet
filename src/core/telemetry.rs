use crate::core::config::Config;
use anyhow::{Context, Result};
use dirs::home_dir;
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// Struct written for each action executed by Magnet.
#[derive(Serialize)]
pub struct ActionRecord {
    pub test_id: String,
    pub timestamp: String,
    pub action: String,
    pub status: String,
    pub details: String,
    /// Optional artifact path (e.g., desktop file path)
    pub artifact_path: Option<String>,
}

/// Get the telemetry directory: %USERPROFILE%\Documents\MagnetTelemetry
pub fn telemetry_dir() -> Option<PathBuf> {
    if let Some(mut p) = home_dir() {
        p.push("Documents");
        p.push("MagnetTelemetry");
        Some(p)
    } else {
        None
    }
}

/// Write both JSONL and human-readable log for an ActionRecord.
/// Non-fatal: returns an Err if it couldn't write.
pub fn write_action_record(cfg: &Config, rec: &ActionRecord) -> Result<()> {
    let dir = telemetry_dir().ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
    create_dir_all(&dir).with_context(|| format!("creating telemetry directory {}", dir.display()))?;

    // JSONL file
    let mut jsonl_path = dir.clone();
    jsonl_path.push(format!("magnet_actions_{}.jsonl", cfg.test_id));
    let mut jf = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&jsonl_path)
        .with_context(|| format!("opening telemetry file {}", jsonl_path.display()))?;
    let j = serde_json::to_string(rec)?;
    writeln!(jf, "{}", j)?;

    // Human-readable log
    let mut log_path = dir;
    log_path.push(format!("magnet_actions_{}.log", cfg.test_id));
    let mut lf = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening human log {}", log_path.display()))?;

    writeln!(lf, "================================================================")?;
    writeln!(lf, "TEST ID   : {}", rec.test_id)?;
    writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
    writeln!(lf, "ACTION    : {}", rec.action)?;
    writeln!(lf, "STATUS    : {}", rec.status)?;
    if !rec.details.is_empty() {
        writeln!(lf, "DETAILS   : {}", rec.details)?;
    }
    if let Some(path) = &rec.artifact_path {
        writeln!(lf, "ARTIFACT  : {}", path)?;
    }
    writeln!(lf)?;

    Ok(())
}
