use ed25519_dalek::{
    Keypair, PublicKey, Signature, SignatureError, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use frame_common::{
    crypto::{AccountId, Ed25519ChallengeResponse},
    traits::State,
};
use frame_treekem::{DhPubKey, EciesCiphertext};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use web3::types::H256;

// ----------------------
//  GET and POST types
// ----------------------

pub mod state {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, Deserialize, Serialize)]
        pub struct Request {
            pub encrypted_req: EciesCiphertext,
        }

        impl Request {
            pub fn new(encrypted_req: EciesCiphertext) -> Self {
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
            pub encrypted_req: EciesCiphertext,
        }

        impl Request {
            pub fn new(encrypted_req: EciesCiphertext) -> Self {
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
        pub struct Response(pub DhPubKey);
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
            pub encrypted_req: EciesCiphertext,
        }

        impl Request {
            pub fn new(encrypted_req: EciesCiphertext) -> Self {
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
