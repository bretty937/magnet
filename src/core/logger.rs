use colored::*;
use std::time::Duration;

/// Initialize logger (enable ANSI on Windows admin shells)
pub fn init() {
    #[cfg(windows)]
    enable_ansi_colors();
}

#[cfg(windows)]
fn enable_ansi_colors() {
    use winapi::um::consoleapi::{GetConsoleMode, SetConsoleMode};
    use winapi::um::processenv::GetStdHandle;
    use winapi::um::winbase::STD_OUTPUT_HANDLE;
    use winapi::um::wincon::ENABLE_VIRTUAL_TERMINAL_PROCESSING;

    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: u32 = 0;

        if GetConsoleMode(handle, &mut mode) != 0 {
            SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
}

/// Print the app header
pub fn header(version: &str) {
    let crown = "🧲".bright_red();
    let title = format!(" MAGNET —  Purple-team telemetry & simulation toolkit v{}", version)
        .bold()
        .on_bright_magenta()
        .white();
    let line = "══════════════════════════════════════════════════════════════════════════";
    println!("{}  {}", crown, title);
    println!("{}", line.bright_black());
}

/// Print a section header for a module
pub fn module_start(name: &str) {
    let left = "⟦".bright_cyan();
    let right = "⟧".bright_cyan();
    let nm = format!(" {} ", name).bold().bright_white();
    println!();
    println!("{}{}{}", left, nm, right);
}

/// Print an action in a tidy single line (action -> result)
pub fn action_running(action: &str) {
    let arrow = "  →".bright_black();
    let act = format!(" {}", action).white();
    print!("{}{}", arrow, act);
}

/// Print that the action succeeded
pub fn action_ok() {
    let ok = " ✅".bright_green().bold();
    println!("   {}", ok);
}

/// Print that the action failed
pub fn action_fail(msg: &str) {
    let fail = " ❌".bright_red().bold();
    println!("   {} {}", fail, msg.bright_red());
}

/// Print an info line
pub fn info(msg: &str) {
    println!("   {}", msg.dimmed());
}

/// Print a warning
pub fn warn(msg: &str) {
    let w = "⚠".yellow();
    println!("{} {}", w, msg.yellow());
}

/// Print an error
pub fn error(msg: &str) {
    let e = "✖".red();
    println!("{} {}", e, msg.red().bold());
}

/// Final summary footer
pub fn summary(elapsed: Duration) {
    let trophy = "🏁".bright_magenta();
    let secs = elapsed.as_secs_f64();
    let footer = format!("Finished — {:.3}s", secs).bold().bright_white();
    println!();
    println!("{} {}", trophy, footer.on_bright_black());
}
