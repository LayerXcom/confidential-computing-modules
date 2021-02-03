use frame_sodium::{SodiumCiphertext, SodiumPubKey};
use serde::{Deserialize, Serialize};
use web3::types::H256;

// ----------------------
//  GET and POST types
// ----------------------

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

pub mod deploy {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response {
            pub contract_address: String,
        }
    }
}

pub mod join_group {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize, Debug)]
        pub struct Request {
            pub contract_address: String,
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub tx_hash: H256,
        }
    }
}

pub mod update_mrenclave {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize, Debug)]
        pub struct Request {
            pub contract_address: String,
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub tx_hash: H256,
        }
    }
}

pub mod encryption_key {
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

pub mod contract_addr {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize, Debug)]
        pub struct Request {
            pub contract_address: String,
        }

        impl Request {
            pub fn new(contract_address: String) -> Self {
                Request { contract_address }
            }
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

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct Request {
            pub contract_address: String,
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response {
            pub tx_hash: H256,
        }
    }
}
