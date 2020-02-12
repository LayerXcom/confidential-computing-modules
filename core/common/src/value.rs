use crate::serde::{Serialize, Deserialize};


#[derive(Clone, Copy, Debug, Default, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(crate = "crate::serde")]
pub struct Value(u64);

impl Value {
    pub fn new(raw: u64) -> Self {
        Value(raw)
    }

    pub fn into_raw(self) -> u64 {
        self.0
    }
}
