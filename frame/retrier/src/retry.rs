use crate::localstd::{result::Result, time::Duration};
use crate::strategy::Strategy;

pub struct Retry {
    tries: usize,
    strategy: Strategy,
}

impl Retry {
    pub fn new(tries: usize, strategy: Strategy) -> Self {
        Self { tries, strategy }
    }

    pub fn spawn<O, T, E>(&self, operation: O) -> Result<T, E>
    where
        O: FnOnce() -> Result<T, E>,
    {
        
        unimplemented!();
    }
}

