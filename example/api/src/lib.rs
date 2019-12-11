
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
        use rand::Rng;
        use ed25519_dalek::{Keypair, PUBLIC_KEY_LENGTH};

        #[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Request {
            pub sig: Vec<u8>,
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

                Request {
                    sig: sig.to_bytes()[..].to_vec(),
                    pubkey: keypair.public.to_bytes(),
                    nonce,
                    total_supply,
                }
            }
        }

        #[derive(Debug, Clone, Eq, PartialEq, Hash, Default, Deserialize, Serialize)]
        pub struct Response(pub [u8; 20]);
    }
}
