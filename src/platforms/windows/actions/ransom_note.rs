use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use anyhow::{Context, Result};
use chrono::Utc;
use dirs::desktop_dir;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

/// Create a benign "ransom note" text file on the current user's Desktop.
/// The content is clearly labeled as a test artifact with MAGNET metadata.
#[derive(Default)]
pub struct RansomNote;

impl RansomNote {
    fn build_note_content(test_id: &str) -> String {
        let now = Utc::now().to_rfc3339();
        let lines = vec![
            "=== MAGNET RANSOM-NOTE SIMULATION ===".to_string(),
            "".to_string(),
            "THIS IS A BENIGN TEST ARTIFACT CREATED BY THE MAGNET TOOL.".to_string(),
            "DO NOT RESPOND — this file is safe and created for purple-team testing.".to_string(),
            "".to_string(),
            format!("MAGNET-TEST-ID: {}", test_id),
            format!("TIMESTAMP: {}", now),
            "".to_string(),
            "To the SOC: This artifact is used to validate detection, ingestion and response.".to_string(),
            "".to_string(),
            "=== END OF NOTE ===".to_string(),
        ];
        lines.join("\r\n")
    }

    fn desktop_path() -> Option<PathBuf> {
        desktop_dir()
    }

    fn note_path(desktop: &PathBuf) -> PathBuf {
        desktop.join("RANSOM_NOTE.txt")
    }
}

impl Simulation for RansomNote {
    fn name(&self) -> &'static str {
        "windows::ransom_note"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let test_id = &cfg.test_id;
        let content = Self::build_note_content(test_id);

        let desktop = Self::desktop_path().context("could not determine Desktop path")?;
        let path = Self::note_path(&desktop);

        // Dry-run: only print what would be written.
        if cfg.dry_run {
            println!("[ransom_note][dry-run] Would write to: {}", path.display());
            println!("[ransom_note][dry-run] Content:\n{}", content);

            // still record an action entry to telemetry in dry-run mode
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "ransom_note".into(),
                status: "dry-run".into(),
                details: "dry-run: no file written".into(),
                artifact_path: Some(path.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            return Ok(());
        }

        println!("[ransom_note] Writing test ransom note to: {}", path.display());

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .with_context(|| format!("failed to open file {}", path.display()))?;

        file.write_all(content.as_bytes())
            .with_context(|| format!("failed to write to {}", path.display()))?;

        println!("[ransom_note] Done. MAGNET-TEST-ID: {}", test_id);

        // Write telemetry record for this action
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "ransom_note".into(),
            status: "written".into(),
            details: format!("Wrote ransom note to Desktop: {}", path.display()),
            artifact_path: Some(path.display().to_string()),
        };

        if let Err(e) = write_action_record(cfg, &rec) {
            println!("[ransom_note] Warning: failed to write telemetry record: {}", e);
        }

        Ok(())
    }
}
