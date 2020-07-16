
/// Generating a random number inside the enclave.
#[cfg(feature = "sgx")]
pub fn sgx_rand_assign(rand: &mut [u8]) -> Result<(), Error> {
    use sgx_trts::trts::rsgx_read_rand;
    rsgx_read_rand(rand)
        .map_err(|e| anyhow!("error rsgx_read_rand: {:?}", e))?;
    Ok(())
}
