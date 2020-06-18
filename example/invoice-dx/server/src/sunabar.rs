use std::collections::HashMap;
use reqwest::{Client, header};
use anyhow::{Result, anyhow};
use anonify_runtime::{Bytes, UpdatedState};

lazy_static! {
    static ref SUNABAR_SECRET: String = {
        use std::env;
        let secret = env::var("SUNABAR_SECRET").unwrap();
        format!("{}{}", "Bearer ", secret)
    };
}

#[derive(Debug, Clone)]
pub struct SunabarClient {
    inner: Client,
    total_amount: Some(u32),

}

impl SunabarClient {
    pub fn new() -> Self {
        let mut headers = header::HearderMap::new();
        headers.insert("Accept", header::HeaderValue::from_static("application/json;charset=UTF-8"));
        headers.insert("x-access-token", header::HeaderValue::from_static(&SUNABAR_SECRET));

        let client = Client::

    }


}
