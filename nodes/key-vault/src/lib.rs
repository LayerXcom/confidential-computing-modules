use key_vault_host::Dispatcher;
use sgx_types::sgx_enclave_id_t;

pub mod handlers;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct Server {
    pub eid: sgx_enclave_id_t,
    pub dispatcher: Dispatcher,
}

impl Server {
    pub fn new(eid: sgx_enclave_id_t) -> Self {
        let dispatcher = Dispatcher::new(eid).unwrap();
        Server { eid, dispatcher }
    }

    pub async fn run(mut self) -> Self {
        let dispatcher = self.dispatcher.start().await.unwrap().set_healthy();

        self.dispatcher = dispatcher;
        self
    }
}
