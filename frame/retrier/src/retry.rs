use crate::localstd::{result::Result, thread, time::Duration};

pub struct Retry<I: Iterator<Item = Duration>> {
    tries: usize,
    strategy: I,
}

impl<I: Iterator<Item = Duration>> Retry<I> {
    pub fn new(tries: usize, strategy: I) -> Self {
        Self { tries, strategy }
    }

    pub fn spawn<O, T, E>(self, mut operation: O) -> Result<T, E>
    where
        O: FnMut() -> Result<T, E>,
    {
        let mut iterator = self.strategy.take(self.tries).into_iter();
        loop {
            match operation() {
                Ok(value) => return Ok(value),
                Err(err) => {
                    if let Some(delay) = iterator.next() {
                        thread::sleep(delay);
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }
}
