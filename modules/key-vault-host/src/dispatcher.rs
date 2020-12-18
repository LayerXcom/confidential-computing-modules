use crate::workflow::*;
use crate::{
    cache::EventCache,
    error::{HostError, Result},
    traits::*,
    utils::*,
    workflow::host_input,
};
use frame_common::{crypto::ExportPathSecret, state_types::UpdatedState, traits::*};
use frame_host::engine::HostEngine;
use frame_mra_tls::primitives::{Certificate, PrivateKey};
use frame_treekem::{DhPubKey, EciesCiphertext};
use parking_lot::RwLock;
use sgx_types::sgx_enclave_id_t;
use std::{fmt::Debug, marker::Send, path::Path};
use web3::types::{Address, H256};

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

    pub fn start(&self, private_key: PrivateKey, certificates: Vec<Certificate>) -> Result<()> {
        let inner = self.inner.read();
        let input = host_input::StartServer::new(private_key, certificates);
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
