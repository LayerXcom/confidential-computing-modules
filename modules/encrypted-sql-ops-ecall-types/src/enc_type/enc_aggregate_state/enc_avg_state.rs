use crate::{
    enc_type::EncInteger,
    serde::{Deserialize, Serialize},
};

/// Intermediate state to calculate average (Encrypted).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct EncAvgState {
    sum: EncInteger,
    n: EncInteger,
}
