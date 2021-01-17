use crate::local_once_cell::sync::Lazy;
use crate::localstd::{
    env,
    string::{String, ToString},
};

pub static REQUEST_RETRIES: Lazy<usize> = Lazy::new(|| {
    env::var("REQUEST_RETRIES")
        .unwrap_or_else(|_| "10".to_string())
        .parse::<usize>()
        .unwrap()
});

pub static RETRY_DELAY_MILLS: Lazy<u64> = Lazy::new(|| {
    env::var("RETRY_DELAY_MILLS")
        .unwrap_or_else(|_| "100".to_string())
        .parse::<u64>()
        .unwrap()
});

pub static PATH_SECRETS_DIR: Lazy<String> =
    Lazy::new(|| env::var("PATH_SECRETS_DIR").unwrap_or(".anonify/pathsecrets".to_string()));
