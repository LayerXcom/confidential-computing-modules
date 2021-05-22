use super::host_output;
use frame_host::engine::HostInput;
use module_encrypted_sql_ops_ecall_types::enclave_types::RawInteger as EnclaveRawInteger;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct RawInteger(i32);

impl HostInput for RawInteger {
    type EcallInput = EnclaveRawInteger;
    type HostOutput = host_output::EncIntegerWrapper;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
        Ok((
            EnclaveRawInteger::from(self.0),
            host_output::EncIntegerWrapper(None),
        ))
    }

    fn ecall_cmd(&self) -> u32 {
        todo!()
    }
}
