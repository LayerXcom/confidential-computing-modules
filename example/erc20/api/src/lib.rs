use ed25519_dalek::{
    Keypair, PublicKey, Signature, SignatureError, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH,
};
use frame_common::{
    crypto::{AccountId, Ed25519ChallengeResponse, ClientCiphertext},
    traits::State,
};
use frame_ecies::DhPubKey;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;
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
            pub encrypted_req: ClientCiphertext,
        }

        impl Request {
            pub fn new(encrypted_req: ClientCiphertext) -> Self {
                Request { encrypted_req }
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub H256);
    }

    pub mod get {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
        }

        impl Request {
            pub fn new<R: Rng>(keypair: &Keypair, rng: &mut R) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                }
            }

            pub fn into_access_right(&self) -> Result<Ed25519ChallengeResponse, SignatureError> {
                let sig = Signature::from_bytes(&self.sig)?;
                let pubkey = PublicKey::from_bytes(&self.pubkey)?;

                Ok(Ed25519ChallengeResponse::new(sig, pubkey, self.challenge))
            }
        }

        impl fmt::Debug for Request {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?} }}",
                    &self.sig[..],
                    self.pubkey,
                    self.challenge
                )
            }
        }

        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response<S: State>(#[serde(deserialize_with = "S::deserialize")] pub S);
    }
}

pub mod deploy {
    pub mod post {
        use super::super::*;
        big_array! { BigArray; }

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

pub mod allowance {
    pub mod get {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
            pub spender: AccountId,
        }

        impl Request {
            pub fn new<R: Rng>(keypair: &Keypair, spender: AccountId, rng: &mut R) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                    spender,
                }
            }

            pub fn into_access_right(&self) -> Result<Ed25519ChallengeResponse, SignatureError> {
                let sig = Signature::from_bytes(&self.sig)?;
                let pubkey = PublicKey::from_bytes(&self.pubkey)?;

                Ok(Ed25519ChallengeResponse::new(sig, pubkey, self.challenge))
            }
        }

        impl fmt::Debug for Request {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?}, spender: {:?} }}",
                    &self.sig[..],
                    self.pubkey,
                    self.challenge,
                    self.spender
                )
            }
        }

        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response<S: State>(#[serde(deserialize_with = "S::deserialize")] pub S);
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
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
        }

        impl Request {
            pub fn new<R: Rng>(keypair: &Keypair, rng: &mut R) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                }
            }

            pub fn into_access_right(&self) -> Result<Ed25519ChallengeResponse, SignatureError> {
                let sig = Signature::from_bytes(&self.sig)?;
                let pubkey = PublicKey::from_bytes(&self.pubkey)?;

                Ok(Ed25519ChallengeResponse::new(sig, pubkey, self.challenge))
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
