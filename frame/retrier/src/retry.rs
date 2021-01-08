use crate::localstd::{result::Result, thread, time::Duration};
use tracing::warn;

pub struct Retry<'a, I: Iterator<Item = Duration>, E: Clone + PartialEq> {
    name: &'a str,
    tries: usize,
    strategy: I,
    condition: Option<&'a E>,
}

impl<'a, I: Iterator<Item = Duration>, E: Clone + PartialEq> Retry<'a, I, E> {
    pub fn new(name: &'a str, tries: usize, strategy: I) -> Self {
        Self {
            name,
            tries,
            strategy,
            condition: None,
        }
    }

    /// Optionally, define error type to retry
    pub fn set_condition(mut self, conditon: &'a E) -> Self {
        self.condition = Some(conditon);
        self
    }

    /// Retry a given operation a certain number of times.
    /// The interval depends on the delay strategy.
    pub fn spawn<O, T>(self, mut operation: O) -> Result<T, E>
    where
        O: FnMut() -> Result<T, E>,
    {
        let mut iterator = self.strategy.take(self.tries).enumerate();
        let condition = self.condition;
        loop {
            match operation() {
                Ok(value) => return Ok(value),
                Err(err) => {
                    // retry if the condition is not set or the error condition is equal with operation's error
                    if condition.is_none() || Some(&err) == condition {
                        if let Some((curr_tries, delay)) = iterator.next() {
                            warn!(
                                "The {} operation retries {} times...",
                                self.name, curr_tries
                            );
                            thread::sleep(delay);
                        } else {
                            return Err(err);
                        }
                    // should not retry if the set error condition is not equal with operation's error
                    } else {
                        return Err(err);
                    }
                }
            }
        }
    }

    #[cfg(feature = "std")]
    pub async fn spawn_async<O, T>(self, mut operation: O) -> Result<T, E>
    where
        O: FnMut() -> Result<T, E>,
    {
        let mut iterator = self.strategy.take(self.tries).enumerate();
        let condition = self.condition;
        loop {
            match operation() {
                Ok(value) => return Ok(value),
                Err(err) => {
                    // retry if the condition is not set or the error condition is equal with operation's error
                    if condition.is_none() || Some(&err) == condition {
                        if let Some((curr_tries, delay)) = iterator.next() {
                            warn!(
                                "The {} operation retries {} times...",
                                self.name, curr_tries
                            );
                            tokio::time::sleep(delay).await;
                        } else {
                            return Err(err);
                        }
                    // should not retry if the set error condition is not equal with operation's error
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
        let res = Retry::<'_>::new("test_counter_success", 4, strategy::FixedDelay::new(10))
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
            Retry::<'_>::new("test_counter_error", 3, strategy::FixedDelay::new(10)).spawn(|| {
                match counter.next() {
                    Some(c) if c == 5 => Ok(c),
                    Some(_) => Err("Some: Not 4"),
                    None => Err("None: Not 4"),
                }
            });

        assert_eq!(res, Err("Some: Not 4"));
    }
}
