use anyhow::Result;
use std::sync::Arc;

use crate::core::simulation::Simulation;
use crate::core::config::Config;

pub struct Runner {
    simulations: Vec<Box<dyn Simulation>>,
    config: Arc<Config>,
}

impl Runner {
    pub fn new(config: Config) -> Self {
        Self {
            simulations: vec![],
            config: Arc::new(config),
        }
    }

    pub fn register(&mut self, sim: Box<dyn Simulation>) {
        self.simulations.push(sim);
    }

    pub fn run_all(&self) -> Result<()> {
        for sim in &self.simulations {
            println!("[runner] Running simulation: {}", sim.name());
            sim.run(&self.config)?;
        }
        Ok(())
    }
}
