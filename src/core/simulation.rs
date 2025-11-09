use anyhow::Result;

/// Common trait every action/simulation must implement.
pub trait Simulation: Send + Sync {
    /// Machine-friendly name
    fn name(&self) -> &'static str;

    /// Execute the simulation. Implementations should be safe and non-destructive.
    fn run(&self, ctx: &crate::core::config::Config) -> Result<()>;
}