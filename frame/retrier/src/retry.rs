use crate::localstd::{fmt, result::Result, thread, time::Duration};
use tracing::warn;

pub struct Retry<I: Iterator<Item = Duration>, E> {
    name: String,
    tries: usize,
    strategy: I,
    condition: Condition<E>,
}

impl<I, E> Retry<I, E>
where
    I: Iterator<Item = Duration>,
    E: fmt::Debug + 'static,
{
    pub fn new(name: impl ToString, tries: usize, strategy: I) -> Self {
        Self {
            name: name.to_string(),
            tries,
            strategy,
            condition: Condition::Always,
        }
    }

    /// Optionally, define condition to retry
    pub fn set_condition<F>(mut self, custom: F) -> Self
    where
        F: Fn(&E) -> bool + 'static,
    {
        self.condition = Condition::Custom(Box::new(custom));
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
                    // retry if the condition is set `always` or the condition is equal with specified operation's error
                    if condition.should_retry(&err) {
                        if let Some((curr_tries, delay)) = iterator.next() {
                            warn!(
                                "The {} operation retries {} times... (error: {:?})",
                                self.name, curr_tries, err
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
                    // retry if the condition is set `always` or the condition is equal with specified operation's error
                    if condition.should_retry(&err) {
                        if let Some((curr_tries, delay)) = iterator.next() {
                            warn!(
                                "The {} operation retries {} times... (error: {:?})",
                                self.name, curr_tries, err
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

enum Condition<E> {
    Always,
    Custom(Box<dyn Fn(&E) -> bool>),
}

impl<E> Condition<E> {
    fn should_retry(&self, err: &E) -> bool {
        match *self {
            Condition::Always => true,
            Condition::Custom(ref cond) => cond(err),
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
        let res = Retry::new("test_counter_success", 4, strategy::FixedDelay::new(10))
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
        let res = Retry::new("test_counter_error", 3, strategy::FixedDelay::new(10)).spawn(|| {
            match counter.next() {
                Some(c) if c == 5 => Ok(c),
                Some(_) => Err("Some: Not 4"),
                None => Err("None: Not 4"),
            }
        });

        assert_eq!(res, Err("Some: Not 4"));
    }
}
