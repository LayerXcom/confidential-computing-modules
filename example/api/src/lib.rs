
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
        use serde::{Deserialize, Serialize};
        use serde_big_array::big_array;
        use rand::Rng;
        use ed25519_dalek::{Keypair, SIGNATURE_LENGTH, PUBLIC_KEY_LENGTH};

        big_array! { BigArray; }

        #[derive(Clone, Deserialize, Serialize)]
        pub struct Request {
            #[serde(with = "BigArray")]
            pub sig: [u8; SIGNATURE_LENGTH],
            pub pubkey: [u8; PUBLIC_KEY_LENGTH],
            pub nonce: [u8; 32],
            pub total_supply: u64,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                total_supply: u64,
                rng: &mut R
            ) -> Self {
                let nonce: [u8; 32] = rng.gen();
                let sig = keypair.sign(&nonce[..]);
                assert!(keypair.verify(&nonce, &sig).is_ok());

                Request {
                    sig: sig.to_bytes(),
                    pubkey: keypair.public.to_bytes(),
                    nonce,
                    total_supply,
                }
            }
        }

        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response(pub [u8; 20]);
    }
}

pub mod send {
    pub mod post {
        use serde::{Deserialize, Serialize};
        use serde_big_array::big_array;
        use rand::Rng;
        use anonify_common::UserAddress;
        use ed25519_dalek::{Keypair, Signature, PublicKey};

        big_array! { BigArray; }

        #[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
        pub struct Request {
            pub sig: Signature,
            pub pubkey: PublicKey,
            pub nonce: [u8; 32],
            pub target: UserAddress,
            pub amount: u64,
        }

        impl Request {
            pub fn new<R: Rng>(
                keypair: &Keypair,
                amount: u64,
                target: UserAddress,
                rng: &mut R,
            ) -> Self {
                let nonce: [u8; 32] = rng.gen();
                let sig = keypair.sign(&nonce[..]);
                assert!(keypair.verify(&nonce, &sig).is_ok());

                Request {
                    sig: sig,
                    pubkey: keypair.public,
                    nonce,
                    target,
                    amount,
                }
            }
        }
    }
}
