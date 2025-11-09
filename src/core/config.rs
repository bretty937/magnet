use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::env;

/// Lightweight config used across simulations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// If true, do not perform filesystem writes; just print what would happen.
    pub dry_run: bool,

    /// A test ID stamped into produced artifacts to aid SOC correlation.
    pub test_id: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dry_run: false,
            test_id: format!("MAGNET-TEST-{}", Utc::now().format("%Y%m%d%H%M%S")),
        }
    }
}

impl Config {
    /// Loads config from environment variables if present.
    /// - MAGNET_DRY_RUN = "1" enables dry-run
    /// - MAGNET_TEST_ID = custom ID
    pub fn load() -> Result<Self> {
        let mut cfg = Config::default();

        if let Ok(v) = env::var("MAGNET_DRY_RUN") {
            if v == "1" || v.eq_ignore_ascii_case("true") {
                cfg.dry_run = true;
            }
        }

        if let Ok(id) = env::var("MAGNET_TEST_ID") {
            if !id.trim().is_empty() {
                cfg.test_id = id;
            }
        }

        Ok(cfg)
    }
}
