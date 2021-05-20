use std::{error::Error, fmt::Display};

/// Enc* 型の復号に失敗した際のエラー
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub(crate) struct DecryptError(String);

impl Error for DecryptError {}
impl Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl DecryptError {
    pub(crate) fn new(message: String) -> Self {
        Self(message)
    }
}
