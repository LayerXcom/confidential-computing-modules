use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Command {
    pub access_policy: [u8; 20],
    pub runtime_params: Params,
    pub cmd_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Params {
    pub other: Vec<u8>,
}

const BLOB_SIZE: usize = 10;

fn main() {
    let ps = Params {
        other: [0u8; BLOB_SIZE].to_vec(),
    };
    let c = Command {
        access_policy: [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        ],
        runtime_params: ps,
        cmd_name: "append_blob".to_string(),
    };

    let json = json!(c);

    let filename = format!("blob.{}.json", BLOB_SIZE);
    let mut file = File::create(filename).unwrap();

    file.write_all(json.to_string().as_bytes()).unwrap();
    file.flush().unwrap();
}
