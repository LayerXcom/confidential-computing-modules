use crate::{error::Result, workflow::*};
use frame_host::engine::HostEngine;
use key_vault_ecall_types::cmd::*;
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use std::sync::Arc;

/// This dispatcher communicates with a mra-tls server.
#[derive(Debug, Clone)]
pub struct Dispatcher {
    inner: Arc<RwLock<InnerDispatcher>>,
}

impl Dispatcher {
    pub fn new(enclave_id: sgx_enclave_id_t) -> Result<Self> {
        let inner = Arc::new(RwLock::new(InnerDispatcher {
            enclave_id,
            is_healthy: false,
        }));

        Ok(Dispatcher { inner })
    }

    pub async fn start(self) -> Result<Self> {
        let eid = self.inner.read().enclave_id;
        let input = host_input::StartServer::new(START_SERVER_CMD);

        let thread_name = format!("Enclave ID:  {}", eid);
        let builder = std::thread::Builder::new().name(thread_name.into());
        builder.spawn(move || {
            let _host_output = StartServerWorkflow::exec(input, eid).unwrap();
        });

        Ok(self)
    }

    pub async fn stop(&self) -> Result<()> {
        let eid = self.inner.read().enclave_id;
        let input = host_input::StopServer::new(STOP_SERVER_CMD);
        let _host_output = StopServerWorkflow::exec(input, eid)?;

        Ok(())
    }

    pub fn set_healthy(self) -> Self {
        self.inner.write().is_healthy = true;
        self
    }

    pub fn is_healthy(&self) -> bool {
        self.inner.read().is_healthy
    }
}

#[derive(Debug, Clone)]
struct InnerDispatcher {
    enclave_id: sgx_enclave_id_t,
    is_healthy: bool,
}
