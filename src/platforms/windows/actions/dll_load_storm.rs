//! DLL Load Storm simulation
//! MITRE: T1574.001 - Hijack Execution Flow: DLL 

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::logger;
use crate::core::telemetry::{ActionRecord, write_action_record};

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;

#[cfg(windows)]
use winapi::um::libloaderapi::FreeLibrary;

#[cfg(windows)]
use winapi::um::libloaderapi::LoadLibraryW;


const MITRE_TTP: &str = "T1574.001";
const MODULE_NAME: &str = "windows::dll_load_storm";

/// DLLs that *actually exist* on Windows
const VALID_DLLS: &[&str] = &[
    "kernel32.dll",
    "user32.dll",
    "advapi32.dll",
    "gdi32.dll",
    "shell32.dll",
    "ole32.dll",
    "crypt32.dll",
    "winhttp.dll",
    "ws2_32.dll",
];

/// DLL names that *do not exist* — simulate malware loaders
const FAKE_DLLS: &[&str] = &[
    "xmrig32.dll",
    "agentloader.dll",
    "mimi64.dll",
    "payload.dll",
    "stage2_beacon.dll",
    "ratimplant.dll",
    "cryptohelper.dll",
];

const LOAD_COUNT: usize = 50;

#[derive(Default)]
pub struct DllLoadStormSimulation;

#[derive(Serialize, Clone)]
pub struct LoadResult {
    timestamp: String,
    dll_name: String,
    success: bool,
}

#[derive(Serialize)]
struct StormSummary {
    test_id: String,
    timestamp: String,
    mitre: String,
    module: String,
    attempted: usize,
    successful: usize,
    failed: usize,
    elapsed_ms: u128,
    parent: String,
}

impl DllLoadStormSimulation {
    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_telemetry(
        cfg: &Config,
        summary: &StormSummary,
        results: &[LoadResult],
    ) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine telemetry dir"))?;
        create_dir_all(&dir)?;

        let mut jsonl = dir.clone();
        jsonl.push(format!("dll_load_storm_{}_per_load.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new().create(true).append(true).open(&jsonl)?;
        for r in results {
            writeln!(jf, "{}", serde_json::to_string(r)?)?;
        }

        let mut summaryf = dir.clone();
        summaryf.push(format!("dll_load_storm_{}_summary.jsonl", cfg.test_id));
        let mut sf = OpenOptions::new().create(true).append(true).open(&summaryf)?;
        writeln!(sf, "{}", serde_json::to_string(summary)?)?;

        let mut logf = dir.clone();
        logf.push(format!("dll_load_storm_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new().create(true).append(true).open(&logf)?;

        writeln!(lf, "===============================================================")?;
        writeln!(lf, "TEST ID     : {}", summary.test_id)?;
        writeln!(lf, "TIMESTAMP   : {}", summary.timestamp)?;
        writeln!(lf, "MODULE      : {}", summary.module)?;
        writeln!(lf, "MITRE TTP   : {}", summary.mitre)?;
        writeln!(lf, "ATTEMPTED   : {}", summary.attempted)?;
        writeln!(lf, "SUCCESSFUL  : {}", summary.successful)?;
        writeln!(lf, "FAILED      : {}", summary.failed)?;
        writeln!(lf, "ELAPSED_MS  : {}", summary.elapsed_ms)?;

        writeln!(lf, "---------------- LOAD RESULTS ----------------")?;
        for r in results {
            writeln!(
                lf,
                "[{}] {} → {}",
                r.timestamp,
                r.dll_name,
                if r.success { "OK" } else { "FAIL" }
            )?;
        }

        writeln!(lf)?;
        Ok(())
    }
}

impl Simulation for DllLoadStormSimulation {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Launching DLL Load Storm...");

        if cfg.dry_run {
            logger::info("dry-run: no DLL loads performed");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
                status: "dry-run".into(),
                details: "DLL load storm skipped".into(),
                artifact_path: None,
            };
            write_action_record(cfg, &rec)?;
            logger::action_ok();
            return Ok(());
        }

        logger::info(&format!(
            "Performing {} rapid LoadLibraryW calls...",
            LOAD_COUNT
        ));

        let mut results: Vec<LoadResult> = Vec::new();
        let start = Instant::now();

        #[cfg(windows)]
        {
            for _i in 0..LOAD_COUNT {
                let dll_name = if fastrand::bool() {
                    VALID_DLLS[fastrand::usize(0..VALID_DLLS.len())]
                } else {
                    FAKE_DLLS[fastrand::usize(0..FAKE_DLLS.len())]
                };

                let timestamp = Utc::now().to_rfc3339();

                // convert to wide
                let wide: Vec<u16> = OsStr::new(dll_name)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                let handle = unsafe { LoadLibraryW(wide.as_ptr()) };
                let ok = !handle.is_null();

                logger::info(&format!(
                    "{} → {}",
                    dll_name,
                    if ok { "OK" } else { "FAIL" }
                ));

                results.push(LoadResult {
                    timestamp,
                    dll_name: dll_name.to_string(),
                    success: ok,
                });

                if ok {
                    unsafe { FreeLibrary(handle) };
                }
            }
        }

        #[cfg(not(windows))]
        {
            logger::warn("Not on Windows: DLL Load Storm skipped");
        }

        let attempted = results.len();
        let successful = results.iter().filter(|r| r.success).count();
        let failed = attempted - successful;
        let elapsed_ms = start.elapsed().as_millis();

        let summary = StormSummary {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            mitre: MITRE_TTP.into(),
            module: MODULE_NAME.into(),
            attempted,
            successful,
            failed,
            elapsed_ms,
            parent: std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or("<unknown>".into()),
        };

        let _ = Self::write_telemetry(cfg, &summary, &results);

        // action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
            status: "completed".into(),
            details: format!("{} ok, {} failed DLL loads", successful, failed),
            artifact_path: None,
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}
