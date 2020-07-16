use frame_common::EcallInput;
use serde::de::DeserializeOwned;

pub trait HostInput: Sized + DeserializeOwned {
    type EcallInput: EcallInput;

    fn from_slice_json(s: &[u8]) -> anyhow::Result<Self> {
        serde_json::from_slice(s).map_err(Into::into)
    }

    fn from_str_json(s: &str) -> anyhow::Result<Self> {
        serde_json::from_str(s).map_err(Into::into)
    }

    fn step(self) -> anyhow::Result<Self::EcallInput>;
}

pub trait HostOutput {}
