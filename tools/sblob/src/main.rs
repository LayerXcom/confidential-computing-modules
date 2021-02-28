use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GetState {
    pub access_policy: NoAuth,
    pub runtime_params: Params,
    pub state_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NoAuth {
    account_id: [u8; 20],
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Params {
    pub blob: Vec<u8>,
}

const BLOB_SIZE: usize = 1_000_000;

fn main() {
    let ps = Params {
        blob: [0u8; BLOB_SIZE].to_vec(),
    };
    let c = GetState {
        access_policy: NoAuth {
            account_id: [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            ],
        },
        runtime_params: ps,
        state_name: "blob_size".to_string(),
    };

    let json = json!(c);

    let filename = format!("sblob.{}.json", BLOB_SIZE);
    let mut file = File::create(filename).unwrap();

    file.write_all(json.to_string().as_bytes()).unwrap();
    file.flush().unwrap();
}
