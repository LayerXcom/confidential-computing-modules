use key_vault_host::Dispatcher;
use sgx_types::sgx_enclave_id_t;

mod api;
mod error;
pub mod handlers;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub struct Server {
    pub eid: sgx_enclave_id_t,
    pub dispatcher: Dispatcher,
}

impl Server {
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        let dispatcher = Dispatcher::new(eid).unwrap();
        Server { eid, dispatcher }
    }
}
