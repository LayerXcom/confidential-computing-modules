use crate::localstd::time::Duration;

#[derive(Debug, Clone, Copy)]
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

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.duration)
    }
}
