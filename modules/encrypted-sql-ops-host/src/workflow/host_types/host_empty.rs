use std::marker::PhantomData;

use frame_host::engine::{HostInput, HostOutput};
use module_encrypted_sql_ops_ecall_types::enclave_types::EnclaveEmpty;

/// Empty input for HostEngine.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct HostEmpty<HO>
where
    HO: HostOutput + Default,
{
    ecall_cmd: u32,
    _ho: PhantomData<HO>,
}

impl<HO> HostInput for HostEmpty<HO>
where
    HO: HostOutput + Default,
{
    type EcallInput = EnclaveEmpty;
    type HostOutput = HO;

    fn apply(self) -> anyhow::Result<(Self::EcallInput, Self::HostOutput)> {
        Ok((EnclaveEmpty, Self::HostOutput::default()))
    }

    fn ecall_cmd(&self) -> u32 {
        self.ecall_cmd
    }
}

impl<HO> HostEmpty<HO>
where
    HO: HostOutput + Default,
{
    /// Constructor
    pub fn new(ecall_cmd: u32) -> Self {
        Self {
            ecall_cmd,
            _ho: PhantomData::default(),
        }
    }
}
