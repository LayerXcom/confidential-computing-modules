use sgx_types::*;
use sgx_urts::SgxEnclave;

pub fn init_enclave() -> SgxResult<SgxEnclave> {
    let launch_token: sgx_launch_token_t = [0; 1024];
    unimplemented!();
}
