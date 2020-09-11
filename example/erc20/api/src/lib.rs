use std::fmt;
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;
use rand::Rng;
use ed25519_dalek::{Keypair, Signature, PublicKey, SignatureError, SIGNATURE_LENGTH, PUBLIC_KEY_LENGTH};
use frame_common::{
    crypto::{Ed25519ChallengeResponse, AccountId},
    traits::State,
};
use web3::types::TransactionReceipt;

// ----------------------
//  GET and POST types
// ----------------------

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
        pub struct Response(pub TransactionReceipt);
    }
}

pub mod init_state {
    pub mod post {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
            pub total_supply: u64,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                total_supply: u64,
                rng: &mut R
            ) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                    total_supply,
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
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?}, total_supply: {:?} }}",
                    &self.sig[..], self.pubkey, self.challenge, self.total_supply
                )
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub TransactionReceipt);
    }
}

pub mod transfer {
    pub mod post {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
            pub target: AccountId,
            pub amount: u64,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                amount: u64,
                target: AccountId,
                rng: &mut R,
            ) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                    target,
                    amount,
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
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?}, target: {:?}, amount: {:?} }}",
                    &self.sig[..], self.pubkey, self.challenge, self.target, self.amount,
                )
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub TransactionReceipt);
    }
}

pub mod approve {
    pub mod post {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
            pub target: AccountId,
            pub amount: u64,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                amount: u64,
                target: AccountId,
                rng: &mut R,
            ) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                    target,
                    amount,
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
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?}, target: {:?}, amount: {:?} }}",
                    &self.sig[..], self.pubkey, self.challenge, self.target, self.amount
                )
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub TransactionReceipt);
    }
}

pub mod transfer_from {
    pub mod post {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
            pub owner: AccountId,
            pub target: AccountId,
            pub amount: u64,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                amount: u64,
                owner: AccountId,
                target: AccountId,
                rng: &mut R,
            ) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                    owner,
                    target,
                    amount,
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
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?}, owner: {:?}, target: {:?}, amount: {:?} }}",
                    &self.sig[..], self.pubkey, self.challenge, self.owner, self.target, self.amount
                )
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub TransactionReceipt);
    }
}

pub mod mint {
    pub mod post {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
            pub target: AccountId,
            pub amount: u64,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                amount: u64,
                target: AccountId,
                rng: &mut R,
            ) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                    target,
                    amount,
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
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?}, target: {:?}, amount: {:?} }}",
                    &self.sig[..], self.pubkey, self.challenge, self.target, self.amount
                )
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub TransactionReceipt);
    }
}

pub mod burn {
    pub mod post {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
            pub amount: u64,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                amount: u64,
                rng: &mut R,
            ) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                    amount,
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
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?}, amount: {:?} }}",
                    &self.sig[..], self.pubkey, self.challenge, self.amount
                )
            }
        }

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub TransactionReceipt);
    }
}

pub mod key_rotation {
    pub mod post {
        use super::super::*;

        #[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
        pub struct Response(pub TransactionReceipt);
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
            pub fn new<R: Rng>(
                keypair: &Keypair,
                spender: AccountId,
                rng: &mut R
            ) -> Self {
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
                    &self.sig[..], self.pubkey, self.challenge, self.spender
                )
            }
        }

        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response<S: State>(pub S);
    }
}

pub mod state {
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
            pub fn new<R: Rng>(
                keypair: &Keypair,
                rng: &mut R
            ) -> Self {
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
                    &self.sig[..], self.pubkey, self.challenge
                )
            }
        }

        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response<S: State>(pub S);
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
            pub fn new<R: Rng>(
                keypair: &Keypair,
                rng: &mut R
            ) -> Self {
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
