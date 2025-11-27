//! Simulates EDR discovery (T1082, T1518, T1057, T1007, T1083)

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{write_action_record, ActionRecord, telemetry_dir};

use anyhow::{Context, Result};
use chrono::Utc;
use regex::Regex;
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Instant;

const EDR_LIST: [&str; 125] = [
    "activeconsole","ADA-PreCheck","ahnlab","amsi.dll","anti malware","anti-malware","antimalware",
    "anti virus","anti-virus","antivirus","appsense","attivo networks","attivonetworks","authtap",
    "avast","avecto","bitdefender","blackberry","canary","carbonblack","carbon black","cb.exe",
    "check point","ciscoamp","cisco amp","countercept","countertack","cramtray","crssvc",
    "crowdstrike","csagent","csfalcon","csshell","cybereason","cyclorama","cylance","cynet",
    "cyoptics","cyupdate","cyvera","cyserver","cytray","darktrace","deep instinct","defendpoint",
    "defender","eectrl","elastic","endgame","f-secure","forcepoint","fortinet","fireeye","groundling",
    "GRRservic","harfanglab","inspector","ivanti","juniper networks","kaspersky","lacuna","logrhythm",
    "malware","malwarebytes","mandiant","mcafee","morphisec","msascuil","msmpeng","nissrv","omni",
    "omniagent","osquery","Palo Alto Networks","pgeposervice","pgsystemtray","privilegeguard",
    "procwall","protectorservic","qianxin","qradar","qualys","rapid7","redcloak","red canary",
    "SanerNow","sangfor","secureworks","securityhealthservice","semlaunchsv","sentinel","sentinelone",
    "sepliveupdat","sisidsservice","sisipsservice","sisipsutil","smc.exe","smcgui","snac64","somma",
    "sophos","splunk","srtsp","symantec","symcorpu","symefasi","sysinternal","sysmon","tanium",
    "tda.exe","tdawork","tehtris","threat","trellix","tpython","trend micro","uptycs","vectra",
    "watchguard","wincollect","windowssensor","wireshark","withsecure","xagt.exe","xagtnotif.exe"
];

const SCAN_DIRS: [&str; 3] = [
    "C:\\Program Files",
    "C:\\Program Files (x86)",
    "C:\\ProgramData",
];

#[derive(Default)]
pub struct EdrDiscoverySimulation;

#[derive(Serialize)]
struct EdrTelemetry {
    test_id: String,
    timestamp: String,
    detections: Vec<String>,
    scan_dirs: Vec<String>,
    elapsed_ms: u128,
    parent: String,
}

fn wmic_list(target: &str) -> Result<Vec<String>> {
    let output = Command::new("wmic")
        .args([target, "get", "name"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to run wmic")?;

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

fn run_edr_scan() -> Result<Vec<String>> {
    let mut detections = Vec::new();
    let regex = Regex::new(&format!("(?i)({})", EDR_LIST.join("|")))?;

    // Processes
    if let Ok(procs) = wmic_list("process") {
        for p in procs {
            if regex.is_match(&p) {
                detections.push(format!("process: {}", p));
            }
        }
    }

    // Services
    if let Ok(svcs) = wmic_list("service") {
        for s in svcs {
            if regex.is_match(&s) {
                detections.push(format!("service: {}", s));
            }
        }
    }

    // Directories
    for dir in SCAN_DIRS {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                if let Some(name) = e.file_name().to_str() {
                    if regex.is_match(name) {
                        detections.push(format!("file: {}\\{}", dir, name));
                    }
                }
            }
        }
    }

    Ok(detections)
}

impl Simulation for EdrDiscoverySimulation {
    fn name(&self) -> &'static str {
        "windows::edr_discovery"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();

        logger::action_running(
            "Running EDR discovery"
        );

        if cfg.dry_run {
            logger::info("dry-run: no discovery performed");

            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1082 - T1518 - T1057 - T1007 - T1083 {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: skipped EDR scan".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        let detections = run_edr_scan()?;

        // ------------------------------------------------------
        // TELEMETRY (PB standard)
        // ------------------------------------------------------
        let telem_dir = telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine telemetry directory"))?;

        fs::create_dir_all(&telem_dir)?;

        // JSONL
        let mut jsonl = telem_dir.clone();
        jsonl.push(format!("edr_discovery_{}.jsonl", cfg.test_id));
        let mut jf = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)?;
        let telem = EdrTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            detections: detections.clone(),
            scan_dirs: SCAN_DIRS.iter().map(|s| s.to_string()).collect(),
            elapsed_ms: start.elapsed().as_millis(),
            parent: std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or("<unknown>".to_string()),
        };
        writeln!(jf, "{}", serde_json::to_string(&telem)?)?;

        // LOG
        let mut log = telem_dir;
        log.push(format!("edr_discovery_{}.log", cfg.test_id));
        let mut lf = fs::OpenOptions::new().create(true).append(true).open(&log)?;
        writeln!(lf, "==============================================================")?;
        writeln!(lf, "TEST ID     : {}", telem.test_id)?;
        writeln!(lf, "TIMESTAMP   : {}", telem.timestamp)?;
        writeln!(lf, "SCAN DIRS   : {:?}", telem.scan_dirs)?;
        writeln!(lf, "DETECTIONS  : {:?}", telem.detections)?;
        writeln!(lf, "ELAPSED_MS  : {}", telem.elapsed_ms)?;
        writeln!(lf, "PARENT      : {}", telem.parent)?;
        writeln!(lf)?;

        // Action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1082 - T1518 - T1057 - T1007 - T1083 {}", self.name()),
            status: "completed".into(),
            details: format!("{} detections found", detections.len()),
            artifact_path: None,
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}
