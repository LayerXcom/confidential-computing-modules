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

#[cfg(test)]
mod tests {
    use crate::*;

    // Ensure the retrier retries 4 times.
    #[test]
    fn test_fixed_delay_strategy_success() {
        let mut counter = 1..=4;
        let res = Retry::new(4, strategy::FixedDelay::new(10)).spawn(|| match counter.next() {
            Some(c) if c == 4 => Ok(c),
            Some(_) => Err("Not 4"),
            None => Err("Not 4"),
        }).unwrap();

        assert_eq!(res, 4);
    }
}
