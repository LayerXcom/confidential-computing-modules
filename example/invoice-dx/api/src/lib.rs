use std::fmt;
use serde::{Deserialize, Serialize};
use serde_big_array::big_array;
use rand::Rng;
use ed25519_dalek::{Keypair, Signature, PublicKey, SignatureError, SIGNATURE_LENGTH, PUBLIC_KEY_LENGTH};
use anonify_common::{AccessRight, UserAddress};
// use anonify_runtime::State;

// ----------------------
//  GET and POST types
// ----------------------

pub mod send_invoice {
    pub mod post {
        use super::super::*;
        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub challenge: [u8; 32],
            pub recipient: UserAddress,
            pub body: String,
            pub state_id: u64,
            pub contract_addr: String,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                state_id: u64,
                recipient: UserAddress,
                body: String,
                contract_addr: String,
                rng: &mut R,
            ) -> Self {
                let challenge: [u8; 32] = rng.gen();
                let sig = keypair.sign(&challenge[..]);
                assert!(keypair.verify(&challenge, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    challenge,
                    recipient,
                    body,
                    state_id,
                    contract_addr,
                }
            }

            pub fn into_access_right(&self) -> Result<AccessRight, SignatureError> {
                let sig = Signature::from_bytes(&self.sig)?;
                let pubkey = PublicKey::from_bytes(&self.pubkey)?;

                Ok(AccessRight::new(sig, pubkey, self.challenge))
            }
        }

        impl fmt::Debug for Request {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(
                    f,
                    "Request {{ sig: {:?}, pubkey: {:?}, challenge: {:?}, recipient: {:?}, body: {:?}, contract address: {:?} }}",
                    &self.sig[..], self.pubkey, self.challenge, self.recipient, self.body, self.contract_addr
                )
            }
        }

        #[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response(pub String);
    }
}

pub mod state {
    pub mod start_polling_moneyforward {
        use super::super::*;

        #[derive(Clone, Deserialize, Serialize, Debug)]
        pub struct Request {}

        impl Request {
            pub fn new() -> Self {
                Request {}
            }
        }
    }
}
