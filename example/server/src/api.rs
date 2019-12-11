
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

        #[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Request {
            pub sig: Vec<u8>,
            pub pubkey: [u8; 32],
            pub nonce: [u8; 32],
            pub total_supply: u64,
        }

        #[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response(pub [u8; 20]);
    }
}
