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
            pub encrypted_req: SodiumCiphertext,
        }

        impl Request {
            pub fn new(encrypted_req: SodiumCiphertext) -> Self {
                Request { encrypted_req }
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub H256);
    }

    pub mod get {
        use super::super::*;

        #[derive(Debug, Clone, Deserialize, Serialize)]
        pub struct Request {
            pub encrypted_req: SodiumCiphertext,
        }

        impl Request {
            pub fn new(encrypted_req: SodiumCiphertext) -> Self {
                Request { encrypted_req }
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
        pub struct Response(pub String);
    }
}

pub mod join_group {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize, Debug)]
        pub struct Request {
            pub contract_addr: String,
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub H256);
    }
}

pub mod update_mrenclave {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize, Debug)]
        pub struct Request {
            pub contract_addr: String,
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub H256);
    }
}

pub mod encrypting_key {
    pub mod get {
        use super::super::*;

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub SodiumPubKey);
    }
}

pub mod key_rotation {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub H256);
    }
}

pub mod contract_addr {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize, Debug)]
        pub struct Request {
            pub contract_addr: String,
        }

        impl Request {
            pub fn new(contract_addr: String) -> Self {
                Request { contract_addr }
            }
        }
    }
}

pub mod register_notification {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, Deserialize, Serialize)]
        pub struct Request {
            pub encrypted_req: SodiumCiphertext,
        }

        impl Request {
            pub fn new(encrypted_req: SodiumCiphertext) -> Self {
                Request { encrypted_req }
            }
        }
    }
}

pub mod register_report {
    pub mod post {
        use super::super::*;

        #[derive(Clone, Debug, Deserialize, Serialize)]
        pub struct Request {
            pub contract_addr: String,
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub H256);
    }
}
