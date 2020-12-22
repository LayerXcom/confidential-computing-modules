use crate::{
    error::Result,
    workflow::*,
};
use frame_host::engine::HostEngine;
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;

/// This dispatcher communicates with a mra-tls server.
#[derive(Debug)]
pub struct Dispatcher {
    inner: RwLock<InnerDispatcher>,
}

impl Dispatcher {
    pub fn new(enclave_id: sgx_enclave_id_t) -> Result<Self> {
        let inner = RwLock::new(InnerDispatcher { enclave_id });

        Ok(Dispatcher { inner })
    }

    pub fn start(&self) -> Result<()> {
        let inner = self.inner.read();
        let input = host_input::StartServer::new();
        let eid = inner.get_enclave_id();
        let _host_output = StartServerWorkflow::exec(input, eid)?;

        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        let inner = self.inner.read();
        let input = host_input::StopServer::default();
        let eid = inner.get_enclave_id();
        let _host_output = StopServerWorkflow::exec(input, eid)?;

        Ok(())
    }
}

#[derive(Debug)]
struct InnerDispatcher {
    enclave_id: sgx_enclave_id_t,
}

impl InnerDispatcher {
    fn get_enclave_id(&self) -> sgx_enclave_id_t {
        self.enclave_id
    }
}
