use crate::config::RuntimeConfig;
// use crate::server
use anyhow::Result;

pub struct Service;

impl Service {
    pub fn start(config: &RuntimeConfig) -> Result<()> {
        let listen_addr = config.listen_addr;



        Ok(())
    }
}
