use std::fs;

use magnet::core::config::Config;
use magnet::core::simulation::Simulation;
use magnet::platforms::windows::actions::ransomware_sim::RansomSimulation;
use dirs::desktop_dir;

/// This test runs the RansomNote simulation and verifies that
/// a file named "RANSOM_NOTE.txt" (or "MAGNET_RANSOM_NOTE.txt")
/// exists on the Desktop after execution.
///
/// ⚠️  Run this test only on authorized systems where you can
/// safely create and delete a benign file on the Desktop.
#[test]
fn test_ransom_note_creates_file_on_desktop() {
    // 1. Resolve Desktop path
    let desktop = desktop_dir().expect("Could not determine Desktop path");

    // 2. Compute expected file path
    let note_path = desktop.join("RANSOM_NOTE.txt");

    // 3. Clean up any leftover file from prior runs
    let _ = fs::remove_file(&note_path);

    // 4. Run the simulation (writes the file)
    let cfg = Config::default();
    let ransom = RansomSimulation::default();
    ransom.run(&cfg).expect("RansomNote simulation failed");

    // 5. Assert the file now exists
    assert!(
        note_path.exists(),
        "Expected ransom note file {:?} to exist",
        note_path
    );

    // 6. Optional: verify content marker
    let content = fs::read_to_string(&note_path)
        .expect("Failed to read ransom note content");
    assert!(
        content.contains("MAGNET-TEST-ID"),
        "Ransom note does not contain test ID marker"
    );

    // 7. Cleanup to keep Desktop tidy
    let _ = fs::remove_file(&note_path);
}
