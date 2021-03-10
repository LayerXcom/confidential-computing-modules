pub async fn deploy<P>(
    &self,
    deploy_user: Address,
    gas: u64,
    abi_path: P,
    bin_path: P,
    confirmations: usize,
) -> Result<String>
where
    P: AsRef<Path> + Send + Sync + Copy,
{
    let contract_addr = inner
        .deployer
        .deploy(&host_output, abi_path, bin_path, confirmations)
        .await?;
    Ok(contract_addr)
}
