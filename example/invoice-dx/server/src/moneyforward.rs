pub const ENDPOINT_BILLINGS: &str = "https://invoice.moneyforward.com/api/v2/billings";

use reqwest::{Client, header};
use serde_json::Value;
use std::collections::HashMap;
use anyhow::{Result, anyhow};

lazy_static! {
    static ref MONEYFORWARD_SECRET: String = {
        use std::env;
        let secret = env::var("MONEYFORWARD_SECRET").unwrap();
        format!("{}{}", "Bearer ", secret)
    };
}

#[derive(Debug, Clone)]
pub struct MFClient {
    inner: Client,
}

impl MFClient {
    pub fn new() -> Self {
        let mut headers = header::HeaderMap::new();
        headers.insert("accept", header::HeaderValue::from_static("application/json"));
        headers.insert("Authorization", header::HeaderValue::from_static(&MONEYFORWARD_SECRET));

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .expect("MFClient builder failed");

        Self { inner: client }
    }

    pub fn get_invoices(&self) -> Result<String> {
        let mut params = HashMap::new();
        params.insert("page", "1");
        params.insert("per_pag", "100");
        params.insert("excise_type", "boolean");

        let res = self.inner
            .get(ENDPOINT_BILLINGS)
            .form(&params)
            .send()?
            .text()?;

        Ok(res)
    }

    pub fn exists_new(&self) -> Result<bool> {
        let resp = self.get_invoices()?;
        let v: Value = serde_json::from_str(&resp)?;
        let n = v["meta"]["total_count"].as_u64()
            .ok_or(anyhow!("total_count not contained in response body"))?;
        Ok(n > 0)
    }
}

// #[derive(Debug, Clone)]
// pub struct Invoice {
//     raw: String,
// }
//
// impl Invoice {
//     pub fn from_response(raw: String) -> Self {
//         Invoice { raw }
//     }
// }
