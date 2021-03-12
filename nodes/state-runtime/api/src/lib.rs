use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use serde::{Deserialize, Serialize};
use web3::types::H256;

// ----------------------
//  GET and POST types
// ----------------------

pub mod user_counter {
    pub mod get {
        use super::super::*;

        #[derive(Debug, Clone, Deserialize, Serialize)]
        pub struct Request {
            pub ciphertext: SodiumCiphertext,
        }

        impl Request {
            pub fn new(ciphertext: SodiumCiphertext) -> Self {
                Request { ciphertext }
            }
        }

        #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
        pub struct Response {
            pub user_counter: serde_json::Value,
        }
    }
}

pub mod state {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, Deserialize, Serialize)]
        pub struct Request {
            pub ciphertext: SodiumCiphertext,
        }

        impl Request {
            pub fn new(ciphertext: SodiumCiphertext) -> Self {
                Request { ciphertext }
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub tx_hash: H256,
        }
    }

    pub mod get {
        use super::super::*;

        #[derive(Debug, Clone, Deserialize, Serialize)]
        pub struct Request {
            pub ciphertext: SodiumCiphertext,
        }

        impl Request {
            pub fn new(ciphertext: SodiumCiphertext) -> Self {
                Request { ciphertext }
            }
        }

        #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
        pub struct Response {
            pub state: serde_json::Value,
        }
    }
}

pub mod join_group {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub tx_hash: H256,
        }
    }
}

pub mod update_mrenclave {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub tx_hash: H256,
        }
    }
}

pub mod enclave_encryption_key {
    pub mod get {
        use super::super::*;

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub enclave_encryption_key: SodiumPubKey,
        }
    }
}

pub mod key_rotation {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub tx_hash: H256,
        }
    }
}

pub mod register_notification {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, Deserialize, Serialize)]
        pub struct Request {
            pub ciphertext: SodiumCiphertext,
        }

        impl Request {
            pub fn new(ciphertext: SodiumCiphertext) -> Self {
                Request { ciphertext }
            }
        }
    }
}

pub mod register_report {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub tx_hash: H256,
        }
    }
}
