use crate::{
    enc_type::EncInteger,
    serde::{Deserialize, Serialize},
};
use frame_common::EcallOutput;


/// Output from enclave
#[derive(Clone, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EncIntegerWrapper(EncInteger);

impl EcallOutput for EncIntegerWrapper {}
