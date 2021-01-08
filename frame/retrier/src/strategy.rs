use crate::localstd::time::Duration;

pub struct FixedDelay {
    duration: Duration,
}

impl FixedDelay {
    pub fn new(mills: u64) -> Self {
        FixedDelay { duration: Duration::from_millis(mills) }
    }
}

impl Iterator for FixedDelay {
    type Item = Duration;

    fn next(&mut self) -> Option<Duration> {
        Some(self.duration)
    }
}
