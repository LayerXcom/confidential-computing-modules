//! Definitions of events from blockchain nodes.

use ethabi::{Event, EventParam, Hash, ParamType};
use once_cell::sync::Lazy;

pub static STORE_TREEKEM_CIPHERTEXT_EVENT: Lazy<Hash> = Lazy::new(|| {
    Event {
        name: "StoreTreeKemCiphertext".to_owned(),
        inputs: vec![
            EventParam {
                name: "ciphertext".to_owned(),
                kind: ParamType::Bytes,
                indexed: true,
            },
            EventParam {
                name: "stateCounter".to_owned(),
                kind: ParamType::Uint(256),
                indexed: true,
            },
        ],
        anonymous: false,
    }
    .signature()
});

pub static STORE_TREEKEM_HANDSHAKE_EVENT: Lazy<Hash> = Lazy::new(|| {
    Event {
        name: "StoreTreeKemHandshake".to_owned(),
        inputs: vec![
            EventParam {
                name: "handshake".to_owned(),
                kind: ParamType::Bytes,
                indexed: true,
            },
            EventParam {
                name: "stateCounter".to_owned(),
                kind: ParamType::Uint(256),
                indexed: true,
            },
        ],
        anonymous: false,
    }
    .signature()
});

pub static JOIN_GROUP_EVENT: Lazy<Hash> = Lazy::new(|| {
    Event {
        name: "JoinGroup".to_owned(),
        inputs: vec![
            EventParam {
                name: "rosterIdx".to_owned(),
                kind: ParamType::Uint(32),
                indexed: true,
            },
            EventParam {
                name: "enclaveEncryptionKey".to_owned(),
                kind: ParamType::FixedBytes(32),
                indexed: true,
            },
        ],
        anonymous: false,
    }
    .signature()
});
