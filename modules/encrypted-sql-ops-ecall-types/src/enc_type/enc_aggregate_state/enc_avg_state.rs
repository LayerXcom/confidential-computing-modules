use crate::{
    enc_type::EncInteger,
    serde::{Deserialize, Serialize},
};

/// State to calculate average (Encrypted).
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub enum EncAvgState {
    /// Intermediate state
    Interm {
        /// current total
        sum: EncInteger,

        /// current number of values
        n: EncInteger,
    },

    /// sum == 0, n == 0
    Initial,
}
