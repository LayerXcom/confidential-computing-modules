use anonify_common::{AccessRight, State};
use sgx_types::sgx_enclave_id_t;
use crate::{
    bridges::ecalls::get_state,
    error::Result,
};

pub fn get_state_by_access_right<S: State>(
    access_right: &AccessRight,
    enclave_id: sgx_enclave_id_t,
) -> Result<S> {
    let state = get_state(
        enclave_id,
        &access_right.sig,
        &access_right.pubkey,
        &access_right.nonce,
    )?;

    Ok(state)
}
