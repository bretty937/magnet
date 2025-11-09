//! magnet - entrypoint
//! IMPORTANT: run only on systems you are authorized to test.

mod core;
mod platforms;

use anyhow::Result;
use core::config::Config;
use core::runner::Runner;
use std::time::Instant; // ✅ new import

fn main() -> Result<()> {
    // Start timer
    let start_time = Instant::now(); // ✅ start

    // Load configuration (defaults if missing).
    let config = Config::load().unwrap_or_default();

    // Create runner
    let mut runner = Runner::new(config);

    // Register platform-specific actions (Windows-only for now)
    #[cfg(target_os = "windows")]
    {
        use platforms::windows::actions::ransom_note::RansomNote;
        runner.register(Box::new(RansomNote::default()));

        use platforms::windows::actions::discovery_sim::DiscoverySim;
        runner.register(Box::new(DiscoverySim::default()));
    }

    println!("[magnet] Starting simulations...");
    runner.run_all()?;
    println!("[magnet] All simulations finished.");

    // ✅ Stop timer and print elapsed duration
    let elapsed = start_time.elapsed();
    println!(
        "[magnet] Total elapsed time: {:.3?} seconds",
        elapsed
    );

    Ok(())
}
