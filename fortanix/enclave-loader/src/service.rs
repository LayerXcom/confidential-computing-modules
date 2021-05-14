use aesm_client::AesmClient;
use enclave_runner::{
    usercalls::{AsyncStream, UsercallExtension},
    EnclaveBuilder,
};
use sgxs_loaders::isgx::Device;

struct HostService {
    socket: String,
}

impl HostService {
    fn new(socket: String) -> Self {
        Self { socket }
    }
}

impl UsercallExtension for HostService {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        local_addr: Option<&'future mut String>,
        peer_addr: Option<&'future mut String>,
    ) -> Pin<Box<dyn Future<Output = IoResult<Option<Box<dyn AsyncStream>>>> + 'future>> {

    }
}
