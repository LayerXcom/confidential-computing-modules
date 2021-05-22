use super::{enclave_input, host_output};
use frame_host::engine::HostInput;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display)]
pub(super) struct RawInteger(i32);

impl HostInput for RawInteger {
    type EcallInput = enclave_input::RawInteger;
    type HostOutput = host_output::EncIntegerWrapper;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
        Ok((self, host_output::EncIntegerWrapper(None)))
    }

    fn ecall_cmd(&self) -> u32 {
        todo!()
    }
}
