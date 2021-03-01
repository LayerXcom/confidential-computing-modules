use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
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
    n: u64,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        panic!("must have 3 args, got {}", args.len());
    }
    let blob_size: usize = args[1].parse().unwrap();
    let n: u64 = args[2].parse().unwrap();

    let ps = Params {
        blob: vec![0u8; blob_size],
        n,
    };
    let c = GetState {
        access_policy: NoAuth {
            account_id: [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
            ],
        },
        runtime_params: ps,
        state_name: "extend_blob_with_n".to_string(),
    };

    let json = json!(c);

    let filename = format!("sblob.{}_{}.json", blob_size, n);
    let mut file = File::create(filename).unwrap();

    file.write_all(json.to_string().as_bytes()).unwrap();
    file.flush().unwrap();
}
