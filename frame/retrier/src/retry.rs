use crate::localstd::{result::Result, thread, time::Duration};
use tracing::warn;

pub struct Retry<'a, I: Iterator<Item = Duration>> {
    tries: usize,
    strategy: I,
    name: &'a str,
}

impl<'a, I: Iterator<Item = Duration>> Retry<'a, I> {
    pub fn new(tries: usize, strategy: I, name: &'a str) -> Self {
        Self {
            tries,
            strategy,
            name,
        }
    }

    pub fn spawn<O, T, E>(self, mut operation: O) -> Result<T, E>
    where
        O: FnMut() -> Result<T, E>,
    {
        let mut iterator = self.strategy.take(self.tries).into_iter().enumerate();
        loop {
            match operation() {
                Ok(value) => return Ok(value),
                Err(err) => {
                    if let Some((curr_tries, delay)) = iterator.next() {
                        warn!(
                            "The {} operation retries {} times...",
                            self.name, curr_tries
                        );
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
    // delay: 10ms
    #[test]
    fn test_fixed_delay_strategy_success() {
        let mut counter = 1..=4;
        let res = Retry::<'_>::new(4, strategy::FixedDelay::new(10), "test_counter_success")
            .spawn(|| match counter.next() {
                Some(c) if c == 4 => Ok(c),
                Some(_) => Err("Not 4"),
                None => Err("Not 4"),
            })
            .unwrap();

        assert_eq!(res, 4);
    }

    // Even if the retrier retries 3 times, the operation should not be successful
    #[test]
    fn test_fixed_delay_strategy_error() {
        let mut counter = 1..=5;
        let res =
            Retry::<'_>::new(3, strategy::FixedDelay::new(10), "test_counter_error").spawn(|| {
                match counter.next() {
                    Some(c) if c == 5 => Ok(c),
                    Some(_) => Err("Some: Not 4"),
                    None => Err("None: Not 4"),
                }
            });

        assert_eq!(res, Err("Some: Not 4"));
    }
}
