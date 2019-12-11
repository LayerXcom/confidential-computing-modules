
// ------------------
//  Response type
// ------------------



// ------------------
//  Query type
// ------------------



// ----------------------
//  GET and POST types
// ----------------------

pub mod deploy {
    pub mod post {
        use serde_derive::{Deserialize, Serialize};

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            total_supply: u64,
            sig: Vec<u8>,
            nonce: [u8; 32],
        }
    }
}
