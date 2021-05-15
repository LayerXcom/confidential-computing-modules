use anyhow::Result;
use serde::{self, Deserialize, Deserializer, Serialize, Serializer};
use std::io::Read;

/// A Message type to communication between enclave and host
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EnclaveMessage {
    /// Unique message identifier
    pub id: u64,
    /// Request or Respone
    pub message_type: MessageType,
    /// Data body of the message
    pub body: Body,
    /// Tracing context serialized in binary format
    #[serde(with = "serde_bytes")]
    pub span_context: Vec<u8>,
}

impl EnclaveMessage {
    pub fn new(id: u64, message_type: MessageType, body: Body, span_context: Vec<u8>) -> Self {
        Self {
            id,
            message_type,
            body,
            span_context,
        }
    }

    pub fn cbor_decode<R: Read>(mut reader: R) -> Result<Self> {
        // TODO: message size check

        serde_cbor::from_reader(reader).map_err(Into::into)
    }

    pub fn cbor_encode(&self) -> Result<Vec<u8>> {
        // TODO: message size check

        serde_cbor::to_vec(self).map_err(Into::into)
    }
}

#[derive(Clone, Copy, Debug)]
// #[repr(u8)]
pub enum MessageType {
    Request = 0,
    Response = 1,
}

impl serde::Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> serde::Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            0 => Ok(MessageType::Request),
            1 => Ok(MessageType::Response),
            _ => Err(serde::de::Error::custom("invalid message type")),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Body {
    Test { test: String },
}
