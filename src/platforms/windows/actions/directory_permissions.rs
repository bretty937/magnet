//! Simulation: Directory Permission Modification (T1222.001).
//!
//! This module simulates an attacker modifying directory access controls by granting
//! "Everyone: Full Control" to the MagnetTelemetry directory for 10 seconds.
//! After that, the added permission entry is removed.
//!


// Once the new ACL is added, you can verify his presence with the following PowerShell command:  
// icacls "$env:USERPROFILE\Documents\MagnetTelemetry" (you should see  Everyone:(F))

use anyhow::{Context, Result};
use chrono::Utc;
use std::path::PathBuf;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};

#[derive(Default)]
pub struct DirectoryPermissionsSim;

impl DirectoryPermissionsSim {
    /// Returns the MagnetTelemetry directory path.
    fn telemetry_dir() -> Result<PathBuf> {
        crate::core::telemetry::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("Could not determine MagnetTelemetry path"))
    }

    /// Grant Everyone full control (recursive).
    fn grant_everyone_full(target: &PathBuf) -> Result<()> {
        let status = Command::new("icacls")
            .arg(target)
            .args(&["/grant", "Everyone:F"])
            .arg("/T")
            .arg("/C")
            .arg("/Q")
            .status()
            .context("failed to run icacls /grant")?;

        if !status.success() {
            return Err(anyhow::anyhow!("icacls /grant failed"));
        }

        Ok(())
    }

    /// Remove Everyone ACE (recursive).
    fn remove_everyone(target: &PathBuf) -> Result<()> {
        let status = Command::new("icacls")
            .arg(target)
            .args(&["/remove", "Everyone"])
            .arg("/T")
            .arg("/C")
            .arg("/Q")
            .status()
            .context("failed to run icacls /remove")?;

        if !status.success() {
            return Err(anyhow::anyhow!("icacls /remove failed"));
        }

        Ok(())
    }
}

impl Simulation for DirectoryPermissionsSim {
    fn name(&self) -> &'static str {
        "windows::directory_permissions"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Modifying directory permissions");

        let start = Instant::now();
        let telemetry_dir = Self::telemetry_dir()?;

        if cfg.dry_run {
            logger::info("[dry-run] Would grant Everyone:F, wait 10s, then remove the ACE.");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "directory_permissions".into(),
                status: "dry-run".into(),
                details: "dry-run: no ACL modified".into(),
                artifact_path: Some(telemetry_dir.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // 1. Apply Everyone:F
        match Self::grant_everyone_full(&telemetry_dir) {
            Ok(_) => logger::info("\nApplied Everyone:F to telemetry directory."),
            Err(e) => {
                logger::action_fail("\nFailed to apply Everyone:F");
                return Err(e);
            }
        }

        // 2. Hold for 10 seconds
        logger::info("Holding insecure permissions for 10 seconds...");
        sleep(Duration::from_secs(10));

        // 3. Remove Everyone ACE
        match Self::remove_everyone(&telemetry_dir) {
            Ok(_) => logger::info("Successfully removed Everyone ACE."),
            Err(e) => {
                logger::action_fail("Failed to remove Everyone ACE");
                return Err(e);
            }
        }

        let elapsed = start.elapsed();

        // 4. Write telemetry record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "T1222.001 - directory_permissions".into(),
            status: "written".into(),
            details: format!(
                "Directory permissions temporarily elevated and then reverted ({} ms).",
                elapsed.as_millis()
            ),
            artifact_path: Some(telemetry_dir.display().to_string()),
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}
